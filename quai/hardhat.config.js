/**
 * SakshyaLog on Quai Network. Mirrors the sponsor's reference project
 * (Yaswitha-Kurra/Quai-Network-Contract-Deploy-Example): Solidity 0.8.20,
 * optimizer 1000 runs, London EVM, IPFS metadata, @quai/hardhat-deploy-metadata.
 *
 * Tests run on the local Hardhat network:   npx hardhat test --network hardhat
 * Deployment targets Orchard Cyprus-1:      npx hardhat run scripts/deploy.js --network cyprus1
 * @type import('hardhat/config').HardhatUserConfig
 */
require('@nomicfoundation/hardhat-toolbox')
require('@quai/hardhat-deploy-metadata')
require('dotenv').config({ path: require('path').join(__dirname, '.env') })

module.exports = {
  defaultNetwork: 'hardhat', // safe default: nothing is broadcast unless --network cyprus1 is given
  networks: {
    cyprus1: {
      url: process.env.RPC_URL || 'https://orchard.rpc.quai.network',
      accounts: process.env.CYPRUS1_PK ? [process.env.CYPRUS1_PK] : [],
      chainId: Number(process.env.CHAIN_ID || 15000),
    },
  },
  solidity: {
    compilers: [
      {
        version: '0.8.20',
        settings: {
          optimizer: { enabled: true, runs: 1000 },
          metadata: { bytecodeHash: 'ipfs', useLiteralContent: true },
          evmVersion: 'london',
        },
      },
    ],
  },
  paths: { sources: './contracts', cache: './cache', artifacts: './artifacts' },
  mocha: { timeout: 60000 },
}
