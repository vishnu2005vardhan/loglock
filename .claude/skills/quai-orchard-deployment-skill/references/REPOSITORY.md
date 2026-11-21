# Reference implementation

Repository: https://github.com/Yaswitha-Kurra/Quai-Network-Contract-Deploy-Example

Inspected on 2026-11-20. Use live repository files for the most recent versions.

- `contracts/MyContract.sol`: OpenZeppelin ERC20 + Ownable token, Workshop Token (WTK), initial 1,000,000 tokens, owner mint, holder burn, and an **unrestricted faucet that mints 100 tokens per call**. This is NOT a capped token; explain before deploying.
- `hardhat.config.js`: default network `cyprus1`, `RPC_URL`, `CYPRUS1_PK`, `CHAIN_ID`, Solidity 0.8.20, optimizer runs 1000, London EVM, IPFS metadata settings, `@quai/hardhat-deploy-metadata`.
- `scripts/deploy.js`: uses `quais.JsonRpcProvider` with `usePathing:true`, `quais.Wallet`, Hardhat `deployMetadata.pushMetadataToIPFS('MyContract')`, `quais.ContractFactory`, deploy/wait/address.
- `package.json`: Hardhat 2.x, quais 1.0.0-alpha.52, OpenZeppelin 5.x, metadata plugin. Its `npm test` is a placeholder and not a real test suite.
- README suggests Orchard Cyprus-1, chain ID 15000, testnet wallet and funded QUAI.

Do not copy `.env` from the upstream repository: it is listed as a tracked file in the public GitHub file tree. Treat any exposed credentials as compromised; never reuse them. Create your own local `.env` and ensure it is ignored.

Source URLs:
- https://github.com/Yaswitha-Kurra/Quai-Network-Contract-Deploy-Example/blob/main/scripts/deploy.js
- https://github.com/Yaswitha-Kurra/Quai-Network-Contract-Deploy-Example/blob/main/hardhat.config.js
- https://github.com/Yaswitha-Kurra/Quai-Network-Contract-Deploy-Example/blob/main/contracts/MyContract.sol
- https://docs.qu.ai/
