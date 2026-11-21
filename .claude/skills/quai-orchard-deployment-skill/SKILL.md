---
name: quai-orchard-contract-deployment
description: Build, customize, compile, test, and deploy QRC-compatible token and custom Solidity contracts on Quai Orchard Cyprus-1 using the Yaswitha-Kurra Hardhat/quais reference implementation. Use for Orchard token deployments, contract creation, or debugging Quai deployments.
---

# Quai Orchard Contract Deployment

## Source of truth
Use https://github.com/Yaswitha-Kurra/Quai-Network-Contract-Deploy-Example as the reference project. Read `references/REPOSITORY.md` before acting. The repository's deployment architecture is the baseline; do not replace `quais.ContractFactory` with `ethers.ContractFactory` or assume Ethereum RPC semantics.

## Supported requests
- Create and customize QRC-compatible fungible, NFT, and multi-token contracts, using established OpenZeppelin ERC20/ERC721/ERC1155 interfaces where appropriate. Do not claim native QRC-specific semantics without checking Quai documentation.
- Accept existing user-written Solidity code, preserve custom logic, and deploy it after review. Never silently replace custom source with a template.
- Compile, test, troubleshoot, deploy, and export deployment evidence on Orchard Cyprus-1.
- Cross-zone SolidityX contracts are outside this skill; explain that they require a different workflow.

## Mandatory workflow
1. Identify whether the user wants a token standard or custom Solidity contract; ask for constructor arguments, owner, token supply, and mint permissions only if missing.
2. Inspect the current project and compare it with the upstream example. If there is no project, instruct user to clone the example; do not invent upstream code.
3. Confirm `hardhat.config.js` uses Solidity 0.8.20, `evmVersion: london`, and `@quai/hardhat-deploy-metadata`, as in the reference. Check upstream for changes before copying configuration.
4. Review Solidity source for ownership, privileged minting, reentrancy, access control, arithmetic, unsafe external calls, and unlimited supply. The upstream example `faucet()` is unrestricted; explain this before reuse.
5. Ensure `.env` is gitignored. Use a fresh testnet wallet. Never print, log, ask to paste, or commit a private key. `.env` should contain `RPC_URL`, `CYPRUS1_PK`, and `CHAIN_ID=15000`. Confirm RPC URL against current official Quai docs and actual connectivity; do not assume old endpoint paths.
6. Install dependencies (`npm install`), compile (`npx hardhat compile`), and run available tests. If the upstream project has no real tests, write tests for constructor, permissions, mint/burn/transfer and failure cases; do not claim `npm test` passes merely because a placeholder script exists.
7. Before any broadcast, confirm network is Orchard Cyprus-1, chain ID 15000, wallet has testnet QUAI, compiled contract name, constructor args, expected privileges, and user approval. Mainnet deployment is forbidden in this skill.
8. Follow the reference deployment design: `quais.JsonRpcProvider(...,{usePathing:true})`, `quais.Wallet`, `deployMetadata.pushMetadataToIPFS(contractName)`, `quais.ContractFactory(abi,bytecode,wallet,ipfsHash)`, `.deploy(...args)`, `.waitForDeployment()`, `.getAddress()`. Ensure metadata plugin and artifact paths match the actual project.
9. After confirmation, run `npx hardhat run scripts/deploy.js --network cyprus1` or the project's verified equivalent. If the upstream script uses a hardcoded contract name, update it for the user's artifact and constructor arguments before running.
10. Return deployed contract address, transaction hash, network/chain ID, deployed artifact ABI path, and verification status. Never claim explorer verification without checking it.

## Stop conditions
Stop on missing approvals, invalid keys, chain mismatch, insufficient testnet balance, failed compilation/tests, unavailable metadata upload, unexpected source changes, or unclear admin powers. Provide actionable diagnostics without bypassing safety checks.

## Additional guidance
Read `references/REPOSITORY.md` and `references/SECURITY.md`. Follow `examples/PROMPTS.md` for participant-facing usage. Run `node scripts/check-project.js <project-directory>` to check local configuration before deployment; it is a static helper, not a replacement for network preflight or security audit.
