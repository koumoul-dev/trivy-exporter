import { strict as assert } from 'node:assert'
import { it, describe } from 'node:test'

import runTrivyScan from '../src/utils/runTrivyScan.js'
import prometheus from '../src/utils/prometheus.js'
import parseCounter from '../src/utils/parseCounters.js'
import getContainers from '../src/utils/getContainers.js'
import app from '../src/app.js'

describe('Trivy exporter', () => {
  describe('Trivy scan', () => {
    it('should list images of running containers', async () => {
      const imageNames = await getContainers()
      console.log(imageNames)

      assert.ok(imageNames.includes('alpine:3.17.0'))
    })

    it('should run Trivy scan', async () => {
      const imageName = 'alpine:3.17.0'
      const result = await runTrivyScan('image', imageName)
      const vulnerabilities = result.Results[0].Vulnerabilities

      assert.ok(vulnerabilities.length > 0)
      assert.ok(vulnerabilities[0].VulnerabilityID.startsWith('CVE-'))
    })

    it('should get metrics from Trivy scan', async () => {
      const gauge = prometheus.vulnerabilitiesGauge
      const imageName = 'alpine:3.17.0'
      const report = await runTrivyScan(imageName)
      const counter = await parseCounter(report)

      for (const result of report.Results) {
        const vulnerabilities = result.Vulnerabilities
        for (const vulnerability of vulnerabilities) {
          const severity = vulnerability.Severity
          const count = counter.find((item) => item.severity === severity)?.count || 0

          gauge.set({ container_name: report.ArtifactName, severity: vulnerability.Severity }, count)
        }
      }
      console.log('Metrics', gauge.hashMap)
      console.log('All scans have been completed')

      assert.ok(gauge.hashMap)
    })

    it('should run all scans', async () => {
      await app.start()
    })

    it('should run Trivy scan root', async () => {
      const result = await runTrivyScan('fs', 'rootfs')
      console.log(result)
    })
  })
})
