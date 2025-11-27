# jsn-sdk-arb: Cross-Chain Bridge Event Listener Simulation

This repository contains a Python script that simulates a critical backend component of a cross-chain bridge. This script acts as a relayer (or validator node) that listens for `TokensLocked` events on a source blockchain (e.g., Ethereum). Upon detecting an event, it initiates a corresponding `mintTokens` transaction on a destination blockchain (e.g., an Arbitrum-like Layer 2 network).

This project is designed as an architectural showcase, demonstrating best practices in modular design, state management, error handling, and interaction with blockchain networks using Python.

## Concept

The core idea is to simulate a "lock-and-mint" cross-chain bridge mechanism. The process begins when the source chain's bridge contract emits a `TokensLocked` event, which might look like this in Solidity:

```solidity
event TokensLocked(
    address indexed user,
    address indexed token,
    uint256 amount,
    bytes32 indexed depositId
);
```

The lifecycle of a cross-chain transfer in this model is as follows:

1.  **Lock**: A user locks tokens (e.g., ERC20) in the bridge contract on the source chain. This action emits a `TokensLocked` event.
2.  **Listen**: Our Python script, running on a server, continuously monitors the source chain for this specific event.
3.  **Verify & Process**: Upon detecting a new `TokensLocked` event, the script parses the event details (user, token, amount, etc.). It can perform additional checks or fetch external data (e.g., token prices for logging).
4.  **Relay & Mint**: The script then constructs, signs, and sends a new transaction to the bridge contract on the destination chain. This transaction calls the `mintTokens` function, creating wrapped tokens equivalent to the ones locked on the source chain and sending them to the user's address on the destination chain.

This script plays the role of the off-chain actor responsible for steps 2, 3, and 4.

## Code Architecture

The script is designed with a clear separation of concerns, organized into several distinct classes:

-   `Config`: A static class that loads and validates all necessary configuration from environment variables (`.env` file). This includes RPC URLs, contract addresses, and the relayer wallet's private key.

-   `StateManager`: Manages the persistence of the listener's state. It reads and writes the last successfully processed block number to a local JSON file (`listener_state.json`). This ensures that if the script restarts, it can resume from where it left off without reprocessing old events or missing new ones.

-   `BlockchainConnector`: A wrapper around `web3.py` that handles the connection to a blockchain node. It encapsulates the Web3 instance and provides clean methods for getting the current block number and creating contract objects. Instances are created for both the source and destination chains.

-   `TransactionManager`: Responsible for all aspects of sending a transaction on the destination chain. It handles nonce calculation, gas estimation, transaction signing (using the provided private key), and broadcasting to the network. It also includes logic for waiting for a transaction receipt to confirm its success or failure.

-   `EventProcessor`: Contains the core business logic. It parses event data, can fetch external information (e.g., token prices via an API), and uses the `TransactionManager` to initiate the `mintTokens` transaction on the destination chain.

-   `BridgeEventListener`: The main orchestrator. It contains the primary loop that periodically polls the source chain for new blocks. It uses the `StateManager` to determine which block range to scan, fetches relevant event logs, and passes each found event to the `EventProcessor` for handling.

### Architectural Flow

```
+-----------------------+
| main() - Entry Point  |
+-----------+-----------+
            |
            v
+-----------------------+
|   Initialize all      |
|   classes (Config,    |
|   Connectors, etc.)   |
+-----------+-----------+
            |
            v
+-----------------------+      +------------------+
| BridgeEventListener   |----->| StateManager     |
| (start_listening loop)|      | (load last block)|      
+-----------+-----------+      +------------------+
            | (loop)
            v
+-----------------------+      +----------------------+
| Poll Source Chain for |----->| BlockchainConnector  |
| `TokensLocked` events |      | (get_logs, get_block)|
+-----------+-----------+      +----------------------+
            | (event found)
            v
+-----------------------+
| EventProcessor        |----->[External API via requests]
| (process_lock_event)  |
+-----------+-----------+
            |
            v
+-----------------------+      +----------------------+
| TransactionManager    |----->| BlockchainConnector  |
| (send_transaction)    |      | (send raw tx)        |
+-----------+-----------+      +----------------------+
            |
            v
+-----------------------+      +------------------+
| Update last processed |----->| StateManager     |
| block and repeat      |      | (save last block)|      
+-----------------------+      +------------------+
```

## How It Works

1.  **Initialization**: The `main()` function is executed. It loads and validates the configuration from the `.env` file, then instantiates all necessary classes, including separate `BlockchainConnector` instances for the source and destination chains.
2.  **State Loading**: The `BridgeEventListener` starts its `start_listening` method. It immediately queries the `StateManager` for the last block number it processed. If no state file exists, it defaults to a recent block.
3.  **Polling Loop**: The listener enters an infinite `while` loop. In each iteration, it:
    a.  Fetches the latest "safe" block number from the source chain (current block minus a confirmation buffer to avoid chain reorgs).
    b.  If the safe block is ahead of the last processed block, it defines a range of blocks to scan (e.g., from `last_processed + 1` up to `safe_block`).
    c.  It uses a `web3.py` contract event filter to efficiently query the RPC node for `TokensLocked` logs within that block range.
    d.  If any events are returned, it iterates through them.
4.  **Event Processing**: For each event, it calls `event_processor.process_lock_event()`.
    a.  The processor extracts the arguments (`user`, `amount`, etc.) from the event log.
    b.  It calls the `mintTokens` function on the destination bridge contract, passing the parsed arguments.
    c.  The `TransactionManager` builds, signs, and sends the transaction to the destination chain.
5.  **State Update**: After scanning a block range (regardless of whether events were found), the listener updates the `StateManager` with the latest block number it scanned (`to_block`). This state is saved to `listener_state.json`.
6.  **Repeat**: The loop waits for a configured poll interval (e.g., 15 seconds) and then repeats from step 3.

## Getting Started

### 1. Prerequisites

*   Python 3.8+
*   Access to RPC URLs for two Ethereum-compatible chains (e.g., from Infura, Alchemy, or a local node). One for the source chain, one for the destination.

### 2. Installation

```bash
# Clone the repository
git clone https://github.com/your-username/jsn-sdk-arb.git
cd jsn-sdk-arb

# Create a virtual environment and activate it
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

# Install the required Python packages
pip install -r requirements.txt
```

### 3. Configuration

Create a file named `.env` in the root of the project directory. Populate it with the necessary details.

```env
# RPC URL for the chain where tokens are locked (e.g., Ethereum Mainnet or Goerli)
SOURCE_CHAIN_RPC_URL="https://goerli.infura.io/v3/YOUR_INFURA_PROJECT_ID"

# RPC URL for the chain where tokens are minted (e.g., Arbitrum Goerli)
DEST_CHAIN_RPC_URL="https://arbitrum-goerli.infura.io/v3/YOUR_INFURA_PROJECT_ID"

# The private key of the relayer's wallet (must have funds on the DESTINATION chain for gas)
# IMPORTANT: For demonstration only. Use a secure key management system in production.
RELAYER_PRIVATE_KEY="0x...your_private_key..."

# Address of the bridge contract on the source chain
SOURCE_BRIDGE_CONTRACT="0x...your_source_contract_address..."

# Address of the bridge contract on the destination chain
DEST_BRIDGE_CONTRACT="0x...your_destination_contract_address..."
```
**Important:** Do not commit the `.env` file to version control.

### 4. Running the Script

Open your terminal in the project directory and run the script:

```bash
python script.py
```

### Expected Output

The script will start logging its activity to the console. You will see messages indicating its connection status, the blocks it's scanning, and any events it finds and processes.

```
2023-10-27 10:30:00,123 - __main__ - INFO - Starting JSN-SDK-ARB Bridge Relayer Simulation.
2023-10-27 10:30:01,456 - __main__ - INFO - Successfully connected to RPC at https://goerli.infura.io/v3/...
2023-10-27 10:30:02,789 - __main__ - INFO - Successfully connected to RPC at https://arbitrum-goerli.infura.io/v3/...
2023-10-27 10:30:02,990 - __main__ - INFO - Transaction Manager initialized for address: 0xRelayerWalletAddress...
2023-10-27 10:30:03,100 - __main__ - INFO - Initializing Bridge Event Listener...
2023-10-27 10:30:03,500 - __main__ - INFO - Starting event listener from block 9500001
2023-10-27 10:30:04,000 - __main__ - INFO - Scanning for 'TokensLocked' events from block 9500001 to 9500500...
2023-10-27 10:30:08,200 - __main__ - INFO - Found 1 new 'TokensLocked' event(s).
2023-10-27 10:30:08,201 - __main__ - INFO - Processing 'TokensLocked' event from block 9500123. User: 0x..., Token: 0x..., Amount: 1000000000000000000, DepositID: 0x...
2023-10-27 10:30:09,300 - __main__ - INFO - External data for token 0x...: Price ~$1500.0 USD
2023-10-27 10:30:09,301 - __main__ - INFO - Attempting to mint tokens on destination chain for deposit 0x...
2023-10-27 10:30:10,500 - __main__ - INFO - Transaction sent. Hash: 0x...
2023-10-27 10:30:25,800 - __main__ - INFO - Transaction 0x... confirmed successfully.
2023-10-27 10:30:25,801 - __main__ - INFO - Successfully processed and relayed event for deposit 0x.... Tx hash: 0x...
...
```