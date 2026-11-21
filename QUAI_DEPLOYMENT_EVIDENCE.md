# Quai Orchard deployment evidence (fill in after a confirmed deployment)

Copy the values from `quai/deployments/orchard-cyprus1.json`. Never include a private key.

| Field | Value |
|---|---|
| Project / team | SakshyaLog / __________________ |
| Contract name | LogAnchor |
| Network | Quai Orchard testnet, Cyprus-1 |
| Chain ID | 15000 |
| Contract address | __________________ |
| Transaction hash | __________________ |
| Block number | __________________ |
| Deployer (testnet wallet address) | __________________ |
| IPFS metadata hash | __________________ |
| ABI / artifact path | `quai/artifacts/contracts/LogAnchor.sol/LogAnchor.json` (copy: `quai/deployments/LogAnchor.abi.json`) |
| Explorer link | https://orchard.quaiscan.io/address/__________________ |
| Explorer verification status | NOT CHECKED (change only after checking it yourself) |
| GitHub repository link | __________________ |

## Security assumptions and privileged roles
- **Owner** (deployer wallet = SakshyaLog vault) is the only account that can write: anchor roots, heartbeat, attest agents, declare incidents, mark reports.
- The owner **cannot** modify or delete anything already written. Roots are write-once, batches must be continuous, and the CERT-In deadline and on-time flag are computed by the contract.
- No token, mint, withdraw, upgrade, self-destruct or external calls. A compromised owner key could add *new* false records, but could not rewrite history. Mitigation: dedicated wallet, key only in the vault's `.env`.
- Testnet only. Mainnet deployment is refused by `scripts/deploy.js`.
