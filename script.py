import os
import json
import time
import logging
import sys
from typing import Dict, Any, Optional, List

from dotenv import load_dotenv
from web3 import Web3
from web3.contract import Contract
from web3.middleware import geth_poa_middleware
from web3.exceptions import TransactionNotFound, BlockNotFound
import requests

# --- Configuration Loading ---
load_dotenv()

# --- Basic Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


class Config:
    """A centralized configuration class to hold environment variables and constants."""
    # RPC URLs for source and destination chains
    SOURCE_CHAIN_RPC: Optional[str] = os.getenv("SOURCE_CHAIN_RPC_URL")
    DEST_CHAIN_RPC: Optional[str] = os.getenv("DEST_CHAIN_RPC_URL")

    # Private key for the relayer/validator wallet that will submit transactions on the destination chain.
    # WARNING: Do not use a key with real funds in a production environment without a proper KMS.
    RELAYER_PRIVATE_KEY: Optional[str] = os.getenv("RELAYER_PRIVATE_KEY")

    # Contract addresses for the bridge on both chains
    SOURCE_BRIDGE_CONTRACT: Optional[str] = os.getenv("SOURCE_BRIDGE_CONTRACT")
    DEST_BRIDGE_CONTRACT: Optional[str] = os.getenv("DEST_BRIDGE_CONTRACT")

    # State file to keep track of the last processed block
    STATE_FILE_PATH: str = "listener_state.json"
    
    # Polling interval in seconds
    POLL_INTERVAL: int = 15

    # Number of blocks to look behind from the current head to avoid issues with reorgs
    CONFIRMATION_BLOCKS: int = 6

    # --- Hypothetical Contract ABIs ---
    # In a real-world scenario, these would be loaded from JSON files.
    SOURCE_BRIDGE_ABI: List[Dict] = json.loads('''
    [
        {
            "anonymous": false,
            "inputs": [
                {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
                {"indexed": true, "internalType": "address", "name": "token", "type": "address"},
                {"indexed": false, "internalType": "uint256", "name": "amount", "type": "uint256"},
                {"indexed": false, "internalType": "uint256", "name": "destinationChainId", "type": "uint256"},
                {"indexed": false, "internalType": "bytes32", "name": "depositId", "type": "bytes32"}
            ],
            "name": "TokensLocked",
            "type": "event"
        }
    ]
    ''')

    DEST_BRIDGE_ABI: List[Dict] = json.loads('''
    [
        {
            "inputs": [
                {"internalType": "address", "name": "user", "type": "address"},
                {"internalType": "address", "name": "token", "type": "address"},
                {"internalType": "uint256", "name": "amount", "type": "uint256"},
                {"internalType": "bytes32", "name": "sourceDepositId", "type": "bytes32"}
            ],
            "name": "mintTokens",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        }
    ]
    ''')

    @staticmethod
    def validate_config() -> None:
        """Validates that all necessary environment variables are set."""
        required_vars = [
            "SOURCE_CHAIN_RPC_URL", "DEST_CHAIN_RPC_URL", "RELAYER_PRIVATE_KEY",
            "SOURCE_BRIDGE_CONTRACT", "DEST_BRIDGE_CONTRACT"
        ]
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")


class StateManager:
    """Manages the listener's state, specifically the last processed block number."""
    def __init__(self, state_file: str):
        self.state_file = state_file

    def load_last_processed_block(self, default_start_block: int) -> int:
        """Loads the last processed block from the state file. If not found, returns a default."""
        try:
            with open(self.state_file, 'r') as f:
                state = json.load(f)
                block_number = state.get('last_processed_block')
                if block_number:
                    logger.info(f"Loaded last processed block from state file: {block_number}")
                    return block_number
        except (FileNotFoundError, json.JSONDecodeError):
            logger.warning("State file not found or invalid. Starting from default start block.")
        return default_start_block

    def save_last_processed_block(self, block_number: int) -> None:
        """Saves the given block number to the state file."""
        try:
            with open(self.state_file, 'w') as f:
                json.dump({'last_processed_block': block_number}, f)
                logger.debug(f"Saved last processed block to state file: {block_number}")
        except IOError as e:
            logger.error(f"Failed to save state to {self.state_file}: {e}")


class BlockchainConnector:
    """Handles the connection to a single blockchain via Web3.py."""
    def __init__(self, rpc_url: str):
        self.rpc_url = rpc_url
        self.web3 = None
        self.connect()

    def connect(self) -> None:
        """Establishes a connection to the blockchain node."""
        try:
            self.web3 = Web3(Web3.HTTPProvider(self.rpc_url))
            # Middleware for PoA chains like Goerli, Rinkeby, Polygon, etc.
            self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)
            if not self.web3.is_connected():
                raise ConnectionError("Failed to connect to the blockchain node.")
            logger.info(f"Successfully connected to RPC at {self.rpc_url}")
        except Exception as e:
            logger.error(f"Error connecting to {self.rpc_url}: {e}")
            raise

    def get_contract(self, address: str, abi: List[Dict]) -> Contract:
        """Returns a Web3 contract instance."""
        if not self.web3:
            raise ConnectionError("Web3 instance is not initialized.")
        checksum_address = self.web3.to_checksum_address(address)
        return self.web3.eth.contract(address=checksum_address, abi=abi)

    def get_current_block(self) -> int:
        """Fetches the latest block number from the blockchain."""
        if not self.web3:
            raise ConnectionError("Web3 instance is not initialized.")
        try:
            return self.web3.eth.block_number
        except Exception as e:
            logger.error(f"Failed to get current block number: {e}")
            self.connect() # Attempt to reconnect
            return self.web3.eth.block_number


class TransactionManager:
    """Manages the creation, signing, and sending of transactions."""
    def __init__(self, connector: BlockchainConnector, private_key: str):
        self.web3 = connector.web3
        if not self.web3:
            raise ValueError("Connector's Web3 instance is not available.")
        self.account = self.web3.eth.account.from_key(private_key)
        logger.info(f"Transaction Manager initialized for address: {self.account.address}")

    def send_transaction(self, contract_function) -> Optional[str]:
        """
        Builds, signs, and sends a transaction for a given contract function call.
        Handles nonce management, gas estimation, and error handling.
        """
        try:
            nonce = self.web3.eth.get_transaction_count(self.account.address)
            tx_params = {
                'from': self.account.address,
                'nonce': nonce,
                'gas': 2000000, # A safe high gas limit, should be estimated in production
                'gasPrice': self.web3.eth.gas_price, # Dynamic gas price
            }
            
            # Build the transaction
            transaction = contract_function.build_transaction(tx_params)

            # Sign the transaction
            signed_tx = self.web3.eth.account.sign_transaction(transaction, self.account.key)

            # Send the transaction
            tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            logger.info(f"Transaction sent. Hash: {tx_hash.hex()}")

            # Wait for receipt (optional, but good for confirmation)
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            if receipt.status == 0:
                logger.error(f"Transaction {tx_hash.hex()} failed! Receipt: {receipt}")
                return None
            
            logger.info(f"Transaction {tx_hash.hex()} confirmed successfully.")
            return tx_hash.hex()
        except ValueError as e:
            # This can happen if a transaction reverts, e.g., 'already processed'
            logger.error(f"Transaction simulation failed: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred while sending transaction: {e}")
        return None


class EventProcessor:
    """Processes detected events and triggers actions on the destination chain."""
    def __init__(self, dest_connector: BlockchainConnector, dest_contract: Contract, tx_manager: TransactionManager):
        self.dest_connector = dest_connector
        self.dest_contract = dest_contract
        self.tx_manager = tx_manager

    def get_external_confirmation_data(self, token_address: str) -> Dict[str, Any]:
        """Simulates fetching additional data from an external API (e.g., CoinGecko)."""
        try:
            # This is a placeholder for a real API call.
            # We use a public API to demonstrate the requests library.
            api_url = f"https://api.coingecko.com/api/v3/simple/token_price/ethereum?contract_addresses={token_address}&vs_currencies=usd"
            response = requests.get(api_url, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get(token_address.lower(), {"usd": 0})
        except requests.RequestException as e:
            logger.warning(f"Could not fetch external data for token {token_address}: {e}")
            return {"usd": "unknown"}

    def process_lock_event(self, event: Dict[str, Any]) -> None:
        """
        Handles a single 'TokensLocked' event.
        Parses it, prepares a mint transaction, and sends it via the TransactionManager.
        """
        try:
            args = event['args']
            user = args['user']
            token = args['token']
            amount = args['amount']
            deposit_id = args['depositId'].hex() # Convert bytes to hex string for logging

            logger.info(
                f"Processing 'TokensLocked' event from block {event['blockNumber']}. "
                f"User: {user}, Token: {token}, Amount: {amount}, DepositID: {deposit_id}"
            )
            
            # Fetch external data to enrich the processing logic
            token_price_info = self.get_external_confirmation_data(token)
            logger.info(f"External data for token {token}: Price ~${token_price_info.get('usd')} USD")

            # Prepare the corresponding 'mintTokens' function call on the destination contract
            mint_function = self.dest_contract.functions.mintTokens(
                user, 
                token, 
                amount, 
                event['args']['depositId'] # Pass original bytes32 depositId
            )

            # Use the transaction manager to send the transaction
            logger.info(f"Attempting to mint tokens on destination chain for deposit {deposit_id}...")
            tx_hash = self.tx_manager.send_transaction(mint_function)

            if tx_hash:
                logger.info(f"Successfully processed and relayed event for deposit {deposit_id}. Tx hash: {tx_hash}")
            else:
                logger.error(f"Failed to process and relay event for deposit {deposit_id}. Transaction was not successful.")

        except KeyError as e:
            logger.error(f"Event data is missing a required key: {e}. Event: {event}")
        except Exception as e:
            logger.error(f"An unexpected error occurred during event processing: {e}")


class BridgeEventListener:
    """
    The main orchestrator that listens for events on the source chain and passes them to the processor.
    """
    def __init__(self, source_connector: BlockchainConnector, source_contract: Contract, event_processor: EventProcessor, state_manager: StateManager):
        self.source_connector = source_connector
        self.source_contract = source_contract
        self.event_processor = event_processor
        self.state_manager = state_manager
        self.event_filter = None

    def start_listening(self) -> None:
        """Starts the main event listening loop."""
        logger.info("Initializing Bridge Event Listener...")
        current_block = self.source_connector.get_current_block()
        last_processed_block = self.state_manager.load_last_processed_block(current_block - 100) # Start 100 blocks back if no state
        
        logger.info(f"Starting event listener from block {last_processed_block + 1}")

        while True:
            try:
                # Determine the range of blocks to scan
                # We scan up to N blocks behind the head to avoid reorgs
                latest_safe_block = self.source_connector.get_current_block() - Config.CONFIRMATION_BLOCKS
                
                if latest_safe_block <= last_processed_block:
                    logger.debug("No new safe blocks to process. Waiting...")
                    time.sleep(Config.POLL_INTERVAL)
                    continue

                from_block = last_processed_block + 1
                to_block = min(latest_safe_block, from_block + 500) # Process in chunks of 500 blocks
                
                logger.info(f"Scanning for 'TokensLocked' events from block {from_block} to {to_block}...")

                # Fetch event logs for the given block range
                event_filter = self.source_contract.events.TokensLocked.create_filter(
                    fromBlock=from_block,
                    toBlock=to_block
                )
                events = event_filter.get_all_entries()

                if events:
                    logger.info(f"Found {len(events)} new 'TokensLocked' event(s).")
                    for event in events:
                        self.event_processor.process_lock_event(event)
                else:
                    logger.debug(f"No events found in blocks {from_block}-{to_block}.")
                
                # Update state to the last block we've processed
                last_processed_block = to_block
                self.state_manager.save_last_processed_block(last_processed_block)
                
                # If we are far behind, process next chunk immediately
                if to_block < latest_safe_block:
                    continue

            except BlockNotFound:
                logger.warning("A block was not found, possibly due to a reorg. Re-evaluating block range.")
                # Reset last processed block to a slightly earlier point to be safe
                last_processed_block -= 10
                self.state_manager.save_last_processed_block(last_processed_block)
            except Exception as e:
                logger.error(f"An error occurred in the listening loop: {e}", exc_info=True)
            
            time.sleep(Config.POLL_INTERVAL)


def main():
    """Main entry point for the script."""
    logger.info("Starting JSN-SDK-ARB Bridge Relayer Simulation.")
    
    try:
        # 1. Validate configuration
        Config.validate_config()

        # 2. Initialize connectors for both chains
        source_connector = BlockchainConnector(Config.SOURCE_CHAIN_RPC)
        dest_connector = BlockchainConnector(Config.DEST_CHAIN_RPC)

        # 3. Get contract instances
        source_bridge_contract = source_connector.get_contract(Config.SOURCE_BRIDGE_CONTRACT, Config.SOURCE_BRIDGE_ABI)
        dest_bridge_contract = dest_connector.get_contract(Config.DEST_BRIDGE_CONTRACT, Config.DEST_BRIDGE_ABI)

        # 4. Initialize core components
        state_manager = StateManager(Config.STATE_FILE_PATH)
        tx_manager = TransactionManager(dest_connector, Config.RELAYER_PRIVATE_KEY)
        event_processor = EventProcessor(dest_connector, dest_bridge_contract, tx_manager)
        
        # 5. Initialize and start the main event listener
        listener = BridgeEventListener(source_connector, source_bridge_contract, event_processor, state_manager)
        listener.start_listening()

    except ValueError as e:
        logger.critical(f"Configuration error: {e}")
        sys.exit(1)
    except ConnectionError as e:
        logger.critical(f"Blockchain connection error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Shutdown signal received. Exiting gracefully.")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"An unhandled exception occurred: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
