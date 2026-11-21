// Real tests for the SakshyaLog LogAnchor contract (run on the local Hardhat network).
//   npx hardhat test --network hardhat
const { expect } = require('chai')
const { ethers } = require('hardhat')
const { time } = require('@nomicfoundation/hardhat-network-helpers')
const { anyUint } = require('@nomicfoundation/hardhat-chai-matchers/withArgs')

const MODE = { Normal: 0, HighAlert: 1, Panic: 2, Manual: 3 }
const h = (s) => ethers.id(s) // bytes32 helper
const S = 'server-01@demo'

describe('LogAnchor (SakshyaLog notary)', function () {
  let c, owner, attacker

  beforeEach(async function () {
    ;[owner, attacker] = await ethers.getSigners()
    c = await (await ethers.getContractFactory('LogAnchor')).deploy()
  })

  describe('deployment', function () {
    it('makes the deployer (the vault) the owner', async function () {
      expect(await c.owner()).to.equal(owner.address)
      expect(await c.CERTIN_DEADLINE()).to.equal(6 * 3600)
    })
  })

  describe('anchorBatch: continuous, write-once Merkle roots', function () {
    it('anchors a first batch starting at line 1 and records its time', async function () {
      await expect(c.anchorBatch(S, h('root1'), 1, 10, MODE.Normal))
        .to.emit(c, 'Anchored').withArgs(S, h('root1'), 1, 10, MODE.Normal, anyUint)
      expect(await c.anchoredAt(h('root1'))).to.be.gt(0)
      expect(await c.lastSeq(ethers.keccak256(ethers.toUtf8Bytes(S)))).to.equal(10)
      expect(await c.batchCount()).to.equal(1)
    })

    it('accepts the next continuous batch and records a panic anchor', async function () {
      await c.anchorBatch(S, h('r1'), 1, 10, MODE.Normal)
      await expect(c.anchorBatch(S, h('r2'), 11, 12, MODE.Panic)).to.emit(c, 'Anchored')
        .withArgs(S, h('r2'), 11, 12, MODE.Panic, anyUint)
    })

    it('rejects a gap (skipping log lines)', async function () {
      await c.anchorBatch(S, h('r1'), 1, 10, MODE.Normal)
      await expect(c.anchorBatch(S, h('r2'), 15, 20, MODE.Normal)).to.be.revertedWith('gap: batches must be continuous')
    })

    it('rejects a first batch that does not start at line 1', async function () {
      await expect(c.anchorBatch(S, h('r1'), 5, 10, MODE.Normal)).to.be.revertedWith('gap: batches must be continuous')
    })

    it('rejects re-anchoring the same root (write-once)', async function () {
      await c.anchorBatch(S, h('r1'), 1, 10, MODE.Normal)
      await expect(c.anchorBatch('other@x', h('r1'), 1, 3, MODE.Normal)).to.be.revertedWith('already anchored')
    })

    it('rejects an inverted range', async function () {
      await expect(c.anchorBatch(S, h('r1'), 1, 0, MODE.Normal)).to.be.revertedWith('bad range')
    })

    it('keeps separate servers (streams) independent', async function () {
      await c.anchorBatch('a@1', h('a1'), 1, 5, MODE.Normal)
      await expect(c.anchorBatch('b@1', h('b1'), 1, 3, MODE.Normal)).to.emit(c, 'Anchored')
    })

    it('only the vault can anchor', async function () {
      await expect(c.connect(attacker).anchorBatch(S, h('evil'), 1, 1, MODE.Normal)).to.be.revertedWith('only the vault')
    })
  })

  describe('heartbeat', function () {
    it('records a public heartbeat time', async function () {
      await c.heartbeat(S)
      expect(await c.lastHeartbeat(ethers.keccak256(ethers.toUtf8Bytes(S)))).to.equal(await time.latest())
    })
    it('only the vault can post a heartbeat', async function () {
      await expect(c.connect(attacker).heartbeat(S)).to.be.revertedWith('only the vault')
    })
  })

  describe('agent attestation', function () {
    it('records the agent code hash and flags a changed agent', async function () {
      await expect(c.attestAgent(S, h('code-v1'), h('key'))).to.emit(c, 'AgentAttested')
        .withArgs(S, h('code-v1'), h('key'), false, anyUint)
      await expect(c.attestAgent(S, h('code-SWAPPED'), h('key'))).to.emit(c, 'AgentAttested')
        .withArgs(S, h('code-SWAPPED'), h('key'), true, anyUint)
      expect(await c.attestationCount(S)).to.equal(2)
      expect((await c.getAttestation(S, 0)).codeHash).to.equal(h('code-v1'))
    })
    it('only the vault can attest', async function () {
      await expect(c.connect(attacker).attestAgent(S, h('x'), h('y'))).to.be.revertedWith('only the vault')
    })
  })

  describe('incident registry and CERT-In 6-hour rule', function () {
    it('fixes the declared time and a 6-hour deadline, and anchors the snapshot', async function () {
      await expect(c.declareIncident(S, h('snap'), 'root login + exfiltration')).to.emit(c, 'IncidentDeclared')
      const inc = await c.getIncident(0)
      expect(inc.deadline - inc.declaredAt).to.equal(6n * 3600n)
      expect(inc.snapshotRoot).to.equal(h('snap'))
      expect(await c.anchoredAt(h('snap'))).to.equal(inc.declaredAt)
      expect(await c.incidentCount()).to.equal(1)
    })

    it('marks a report filed within 6 hours as ON TIME', async function () {
      await c.declareIncident(S, h('snap'), 'x')
      await time.increase(5 * 3600)
      await expect(c.markReported(0, h('report'))).to.emit(c, 'IncidentReported').withArgs(0, h('report'), true)
      expect((await c.getIncident(0)).reportedOnTime).to.equal(true)
    })

    it('marks a report filed after 6 hours as LATE (the company cannot change this)', async function () {
      await c.declareIncident(S, h('snap'), 'x')
      await time.increase(7 * 3600)
      await c.markReported(0, h('report'))
      expect((await c.getIncident(0)).reportedOnTime).to.equal(false)
    })

    it('rejects reporting twice', async function () {
      await c.declareIncident(S, h('snap'), 'x')
      await c.markReported(0, h('r'))
      await expect(c.markReported(0, h('r2'))).to.be.revertedWith('already reported')
    })

    it('rejects reporting an incident that does not exist', async function () {
      await expect(c.markReported(5, h('r'))).to.be.reverted
    })

    it('only the vault can declare or report incidents', async function () {
      await expect(c.connect(attacker).declareIncident(S, h('s'), 'x')).to.be.revertedWith('only the vault')
      await c.declareIncident(S, h('s'), 'x')
      await expect(c.connect(attacker).markReported(0, h('r'))).to.be.revertedWith('only the vault')
    })
  })
})
