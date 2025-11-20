import { parseQualifiedName } from '@swimlane/docker-reference'
import cron from 'node-cron'
import { getContainers } from './utils/docker.ts'
import { runScan, parseSeverityCounts } from './utils/trivy.ts'
import * as prometheus from './utils/prometheus.ts'
import { ensureDir, emptyDir, fileExists } from './utils/fs.ts'

const runAllScans = async () => {
  console.log('run all scans')
  await emptyDir('data/reports')
  prometheus.reset()
  const containers = await getContainers()
  const imageNames = [...new Set(containers.map(container => container.image))]

  const scanTargets: { type: 'image' | 'fs', name: string }[] = [...imageNames.map(name => ({ type: 'image' as const, name })), { type: 'fs', name: 'rootfs' }]
  for (const scanTarget of scanTargets) {
    console.log(`scan ${scanTarget.type}/${scanTarget.name}`)
    const report = await runScan(scanTarget.type, scanTarget.name)
    const severityCounts = await parseSeverityCounts(report)

    for (const [severity, count] of Object.entries(severityCounts)) {
      if (scanTarget.type === 'image') {
        const imageRef = parseQualifiedName(scanTarget.name)
        for (const container of containers.filter(container => container.image === scanTarget.name)) {
          prometheus.vulnerabilitiesGauge.set({
            container_name: container.name,
            severity,
            image_registry: imageRef.domain || 'index.docker.io',
            image_repository: imageRef.repository,
            image_tag: imageRef.tag,
            namespace: process.env.NAMESPACE || 'default'
          }, count)
        }
      } else {
        prometheus.vulnerabilitiesGauge.set({
          container_name: `${process.env.VM_NAME || 'vm'}/${scanTarget.name}`,
          severity,
          namespace: process.env.NAMESPACE || 'default'
        }, count)
      }
    }
    console.log('gauge "Trivy image vulnerabilities" ok')

    if (scanTarget.type === 'image') {
      const imageRef = parseQualifiedName(scanTarget.name)
      const results = report.Results || []
      for (const result of results) {
        const vulnerabilities = result.Vulnerabilities || []
        for (const vulnerability of vulnerabilities) {
          for (const container of containers.filter(container => container.image === scanTarget.name)) {
            const v2Scores = Object.values(vulnerability.CVSS || {}).map((item: any) => item.V2Score).filter(score => score !== undefined)
            const v3Scores = Object.values(vulnerability.CVSS || {}).map((item: any) => item.V3Score).filter(score => score !== undefined)
            const allScores = v2Scores.concat(v3Scores)
            const maxScore = Math.max(...allScores)
            const labels: Record<string, string | number | undefined> = {
              container_name: container.name,
              severity: vulnerability.Severity,
              image_registry: imageRef.domain || 'index.docker.io',
              image_repository: imageRef.repository,
              image_tag: imageRef.tag,
              namespace: process.env.NAMESPACE || 'default',
              vuln_id: vulnerability.VulnerabilityID,
              vuln_title: vulnerability.Title
            }
            if (maxScore > 0) labels.vuln_score = maxScore
            prometheus.vulnerabilitiesIDGauge.set(labels, 0)
          }
        }
      }
    } else {
      const results = report.Results || []
      for (const result of results) {
        const vulnerabilities = result.Vulnerabilities || []
        for (const vulnerability of vulnerabilities) {
          const v2Scores = Object.values(vulnerability.CVSS).map((item: any) => item.V2Score).filter(score => score !== undefined)
          const v3Scores = Object.values(vulnerability.CVSS).map((item: any) => item.V3Score).filter(score => score !== undefined)
          const allScores = v2Scores.concat(v3Scores)
          const maxScore = Math.max(...allScores)
          prometheus.vulnerabilitiesIDGauge.set({
            container_name: `${process.env.VM_NAME || 'vm'}/${scanTarget.name}`,
            severity: vulnerability.Severity,
            namespace: process.env.NAMESPACE || 'default',
            vuln_id: vulnerability.VulnerabilityID,
            vuln_score: maxScore,
            vuln_title: vulnerability.Title
          }, 0)
        }
      }
    }
    console.log('gauge "Trivy vulnerability ID" ok')
  }

  await prometheus.store()
  prometheus.reset()
  console.log('all scans completed')
}

let runningScan: Promise<void> | null = null
let stopped = false
export const start = async () => {
  await ensureDir('data')
  if (!(await fileExists('data/metrics.txt'))) {
    await runAllScans()
  }

  await prometheus.start(9000)

  // every day at midnight by default
  cron.schedule(process.env.CRON_RULE || '0 0 0 * * *', async () => {
    if (stopped) return
    if (runningScan) {
      console.log('scan already running, skipping')
      return
    }
    runningScan = runAllScans()
    await runningScan
    runningScan = null
  })
}

export const stop = async () => {
  stopped = true
  if (runningScan) {
    try {
      await runningScan
    } catch (err) {
      // ignore
    }
  }
  await prometheus.stop()
}
