# Orchard deployment checklist

- Deploy only to Orchard Cyprus-1 (expected chain ID 15000), never mainnet.
- Never copy or use credentials committed to any public repository.
- Require explicit human approval immediately before any transaction broadcast.
- Verify owner/admin powers and whether tokens have fixed, capped, or unlimited supply.
- Warn that an unrestricted faucet permits repeated minting; add limits or remove it if not intended.
- Do not present OpenZeppelin ERC compatibility as proof of all Quai QRC behaviors.
- Verify the actual RPC endpoint, chain ID, balance, compiler and plugin versions before use.
- A successful compilation is not a security audit. Test access controls, failures and balances.
- IPFS metadata upload may require service configuration and network connectivity.
- Do not report a contract as verified on an explorer unless independently confirmed.
