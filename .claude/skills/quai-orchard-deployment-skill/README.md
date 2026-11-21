# Quai Orchard Contract Deployment — Agent Skill

A participant-shareable AI coding-agent skill based on the [Yaswitha-Kurra Quai deployment example](https://github.com/Yaswitha-Kurra/Quai-Network-Contract-Deploy-Example).

## Install

Extract the folder `quai-orchard-deployment-skill` into the skills directory of your coding agent:

- Claude Code: `.claude/skills/quai-orchard-deployment-skill/`
- Cursor: `.cursor/skills/quai-orchard-deployment-skill/`
- Codex: `.agents/skills/quai-orchard-deployment-skill/`

Then open a development project and ask: "Use the Quai Orchard Contract Deployment skill to set up the reference example and help me deploy a fixed-supply token to Orchard Cyprus-1."

## Reference project setup

```bash
git clone https://github.com/Yaswitha-Kurra/Quai-Network-Contract-Deploy-Example.git
cd Quai-Network-Contract-Deploy-Example
npm install
npx hardhat compile
```

**Do not use any `.env` that came from the public repository.** Create a fresh local `.env` with your own testnet wallet. Add `.env` to `.gitignore`, confirm the current Orchard RPC URL in official Quai docs, and use `CHAIN_ID=15000`. The agent should write real tests before deployment, as the upstream package has a placeholder test command.

Run `node <path-to-skill>/scripts/check-project.js .` for static checks. This cannot validate live chain connectivity or smart-contract security.

## Scope

QRC-compatible fungible/NFT/multi-token contracts and user-supplied custom Solidity; Orchard Cyprus-1 only. SolidityX cross-zone contracts and mainnet are excluded.

## Status

Skill package and static helper prepared; **not** live-tested against Orchard. Dependencies were not installed and no transaction was broadcast. Test the complete workflow before mass distribution.
