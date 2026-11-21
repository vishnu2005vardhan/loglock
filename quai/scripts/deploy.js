// Deploy SakshyaLog's LogAnchor contract to Quai Orchard Cyprus-1.
// Follows the sponsor's reference design (quais.JsonRpcProvider usePathing, quais.Wallet,
// deployMetadata.pushMetadataToIPFS, quais.ContractFactory with the IPFS hash).
//
//   npx hardhat run scripts/deploy.js --network cyprus1
//
// Safety: runs the read-only preflight first, shows exactly what will be sent, and only
// broadcasts after you type DEPLOY. Mainnet is refused.
const fs = require('fs')
const path = require('path')
const readline = require('readline')
const hre = require('hardhat')
const quais = require('quais')
const { ROOT, DEPLOY_PATH, ORCHARD, loadEnv, loadArtifact, provider } = require('./common')
const { preflight } = require('./preflight')

function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  return new Promise((res) => rl.question(question, (a) => { rl.close(); res(a.trim()) }))
}

async function main() {
  if (hre.network.name !== 'cyprus1') throw new Error('Run with --network cyprus1 (Orchard Cyprus-1).')
  console.log('== Preflight (read-only) ==')
  const pf = await preflight()
  if (!pf.ok) throw new Error('Preflight failed. Nothing was sent.')
  const env = loadEnv()
  if (env.chainId === 9n) throw new Error('Mainnet (chain 9) is not allowed. Use Orchard (15000).')

  const artifact = loadArtifact()
  console.log(`
== About to deploy ==
  Network          : ${ORCHARD.name}  (chain id ${env.chainId})
  RPC              : ${env.rpc}
  Deployer wallet  : ${pf.wallet}  (dedicated testnet wallet)
  Contract         : LogAnchor (contracts/LogAnchor.sol, Solidity 0.8.20, london)
  Constructor args : none
  Admin powers     : the deployer wallet becomes 'owner' (the vault). Only the owner can anchor roots,
                     post heartbeats, attest agents, declare incidents and mark reports. The owner can
                     NOT change or delete anything already written: roots are write-once, batches must be
                     continuous, and the 6-hour CERT-In deadline / on-time flag are computed by the contract.
                     There is no mint, no token, no withdraw, no upgrade and no self-destruct.`)

  const answer = await ask('\nType DEPLOY to broadcast this transaction (anything else cancels): ')
  if (answer !== 'DEPLOY') { console.log('Cancelled. Nothing was sent.'); return }

  console.log('\nUploading contract metadata to Quai IPFS...')
  let ipfsHash = await hre.deployMetadata.pushMetadataToIPFS('LogAnchor')
  let metadataUploaded = !!ipfsHash && ipfsHash.length === 46
  let metadataPath = path.join(ROOT, 'metadata', 'LogAnchor_metadata.json')
  if (!metadataUploaded) {
    if ((process.env.QUAI_METADATA_OFFLINE || '').trim() !== '1') {
      throw new Error(
        'IPFS metadata upload failed (Quai\'s server ipfs.qu.ai did not accept it). Stopping; nothing was sent.\n' +
        '  -> Wait a few minutes and try again.\n' +
        '  -> If ipfs.qu.ai stays down AND the organisers agree, use the backup (see QUAI.md, "IPFS server down"):\n' +
        '       set QUAI_METADATA_OFFLINE=1\n' +
        '       npx hardhat run scripts\\deploy.js --network cyprus1')
    }
    const { localMetadataHash } = require('./metadata-offline')
    const local = await localMetadataHash(hre, 'LogAnchor')
    ipfsHash = local.ipfsHash
    metadataPath = local.metadataPath
    console.log(`\nBACKUP MODE: Quai's IPFS upload failed, so the metadata hash was computed locally.
  IPFS hash (same one the compiler embedded in the bytecode): ${ipfsHash}
  Metadata saved to: ${metadataPath}
  The deployed contract is identical. Only the public IPFS copy of the metadata is missing,
  which explorer verification needs. Upload it later when ipfs.qu.ai works.`)
    const again = await ask('\nType OFFLINE to deploy with the locally computed hash (anything else cancels): ')
    if (again !== 'OFFLINE') { console.log('Cancelled. Nothing was sent.'); return }
  }

  const wallet = new quais.Wallet(env.key, provider(env.rpc))
  const factory = new quais.ContractFactory(artifact.abi, artifact.bytecode, wallet, ipfsHash)
  const contract = await factory.deploy()
  const txHash = contract.deploymentTransaction().hash
  console.log('Transaction broadcasted:', txHash)
  await contract.waitForDeployment()
  const address = await contract.getAddress()
  const receipt = await wallet.provider.getTransactionReceipt(txHash)
  console.log('Contract deployed to:', address)

  const record = {
    project: 'SakshyaLog',
    contract: 'LogAnchor',
    network: ORCHARD.name,
    chainId: Number(env.chainId),
    address,
    transactionHash: txHash,
    blockNumber: receipt ? Number(receipt.blockNumber) : null,
    gasUsed: receipt ? receipt.gasUsed.toString() : null,
    deployer: pf.wallet,
    ipfsMetadataHash: ipfsHash,
    ipfsMetadataUploaded: metadataUploaded,
    metadataFile: path.relative(path.join(ROOT, '..'), metadataPath),
    abiPath: 'quai/artifacts/contracts/LogAnchor.sol/LogAnchor.json',
    explorerAddress: `${ORCHARD.explorer}/address/${address}`,
    explorerTx: `${ORCHARD.explorer}/tx/${txHash}`,
    explorerVerification: 'NOT CHECKED (open the explorer link and confirm before claiming verification)',
    deployedAt: new Date().toISOString(),
  }
  fs.mkdirSync(path.dirname(DEPLOY_PATH), { recursive: true })
  fs.writeFileSync(DEPLOY_PATH, JSON.stringify(record, null, 2))
  fs.copyFileSync(path.join(ROOT, 'artifacts', 'contracts', 'LogAnchor.sol', 'LogAnchor.json'),
                  path.join(ROOT, 'deployments', 'LogAnchor.abi.json'))
  console.log(`\nDeployment evidence saved to quai/deployments/orchard-cyprus1.json`)
  console.log(`Explorer: ${record.explorerTx}`)
  console.log('\nNext: start SakshyaLog on Quai:   python run_demo.py --reset --quai')
}

main().then(() => process.exit(0)).catch((e) => { console.error('\nERROR:', e.message || e); process.exit(1) })
