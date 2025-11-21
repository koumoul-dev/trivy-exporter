import { strict as assert } from 'node:assert'
import { it, describe } from 'node:test'

import { runScan, parseSeverityCounts } from '../src/utils/trivy.ts'
import { getContainers } from '../src/utils/docker.ts'
import { ensureDir } from '../src/utils/fs.ts'
import * as app from '../src/app.ts'

await ensureDir('rootfs')

describe('Trivy exporter', () => {
  describe('Trivy scan', () => {
    it('should list images of running containers', async () => {
      const containers = await getContainers()
      assert.ok(containers.find(c => c.name === 'trivy-exporter-app1-1' && c.image === 'alpine:3.17.0'))
    })

    it('should run Trivy scan', async () => {
      const imageName = 'alpine:3.17.0'
      const result = await runScan('image', imageName)
      const vulnerabilities = result.Results[0].Vulnerabilities

      assert.ok(vulnerabilities.length > 0)
      assert.ok(vulnerabilities[0].VulnerabilityID.startsWith('CVE-'))
    })

    it('should get metrics from Trivy scan', async () => {
      const imageName = 'alpine:3.17.0'
      const report = await runScan('image', imageName)
      const severityCounts = await parseSeverityCounts(report)
      assert.ok(severityCounts!.High! > 10)
    })

    it('should run all scans', async () => {
      await app.start()
    })

    it('should run Trivy scan root', async () => {
      const result = await runScan('fs', 'rootfs')
      assert.equal(result.ArtifactType, 'filesystem')
      assert.ok(result.Results.length >= 1)
      assert.ok(result.Results.find((r: any) => r.Target === 'package-lock.json'))
    })
  })
})
