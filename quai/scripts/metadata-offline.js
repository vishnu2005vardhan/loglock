// BACKUP ONLY: compute the contract's IPFS metadata hash locally, for when Quai's IPFS
// upload server (ipfs.qu.ai) is down. Uses the same libraries and steps as
// @quai/hardhat-deploy-metadata, minus the upload:
//   1. read the IPFS hash that the Solidity compiler embedded in the bytecode
//   2. recompute the hash of the compiler's metadata JSON and check they match
//   3. save the metadata JSON to quai/metadata/ so it can be uploaded later
// The deployed contract is identical either way. Only the public copy of the
// metadata on IPFS is missing until it is uploaded (needed for explorer verification).
const fs = require('fs')
const path = require('path')
const Hash = require('ipfs-only-hash')
const CBOR = require('cbor-x')
const bs58 = require('bs58')
const { splitAuxdata, AuxdataStyle } = require('@ethereum-sourcify/bytecode-utils')
const { arrayify } = require('@ethersproject/bytes')
const { parseFullyQualifiedName } = require('hardhat/utils/contract-names')

async function localMetadataHash(hre, contractName) {
  const artifact = await hre.artifacts.readArtifact(contractName)
  const [, auxdata] = splitAuxdata(artifact.deployedBytecode, AuxdataStyle.SOLIDITY)
  if (!auxdata) throw new Error('No metadata section in bytecode (bytecodeHash must be "ipfs").')
  const decoded = CBOR.decode(arrayify(`0x${auxdata}`))
  if (!decoded.ipfs) throw new Error('Bytecode metadata has no IPFS hash.')
  const embedded = (bs58.default || bs58).encode(decoded.ipfs)

  for (const fqn of await hre.artifacts.getAllFullyQualifiedNames()) {
    const { sourceName, contractName: name } = parseFullyQualifiedName(fqn)
    if (name !== contractName) continue
    const buildInfo = await hre.artifacts.getBuildInfo(fqn)
    const metadata = buildInfo.output.contracts[sourceName][name].metadata
    const computed = await Hash.of(metadata)
    if (computed !== embedded) throw new Error(`Metadata hash mismatch: bytecode ${embedded}, computed ${computed}`)
    const out = path.join(hre.config.paths.root, 'metadata', `${name}_metadata.json`)
    fs.mkdirSync(path.dirname(out), { recursive: true })
    fs.writeFileSync(out, metadata)
    return { ipfsHash: embedded, metadataPath: out }
  }
  throw new Error(`Contract ${contractName} not found in build info.`)
}

module.exports = { localMetadataHash }
