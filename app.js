const fs = require('node:fs/promises')
const { parseQualifiedName } = require('@swimlane/docker-reference')
const cron = require('node-cron')
const getContainers = require('./utils/getContainers')
const runTrivyScan = require('./utils/runTrivyScan')
const prometheus = require('./utils/prometheus')
const parseCounters = require('./utils/parseCounters')

const runAllScans = async () => {
  console.log('run all scans')
  const containers = await getContainers()
  const imageNames = [...new Set(containers.map(container => container.image))]
  const gaugeImageVulnerabilities = prometheus.vulnerabilitiesGauge()
  const gaugeVulnerabilityID = prometheus.vulnerabilitiesIDGauge()

  const scanTargets = [...imageNames.map(name => ({ type: 'image', name })), { type: 'fs', name: 'rootfs' }]
  for (const scanTarget of scanTargets) {
    console.log(`Starting to scan ${scanTarget.type}/${scanTarget.name}`)
    const report = await runTrivyScan(scanTarget.type, scanTarget.name)
    const counters = await parseCounters(report)

    for (const counter of counters) {
      if (scanTarget.type === 'image') {
        const imageRef = parseQualifiedName(scanTarget.name)
        for (const container of containers.filter(container => container.image === scanTarget.name)) {
          container.name[0] = container.name[0].replace('/', '')
          gaugeImageVulnerabilities.set({
            container_name: container.name,
            severity: counter.severity,
            image_registry: imageRef.domain || 'index.docker.io',
            image_repository: imageRef.repository,
            image_tag: imageRef.tag,
            namespace: process.env.VM_NAME || 'trivy-exporter'
          }, counter.count)
        }
      } else {
        gaugeImageVulnerabilities.set({
          container_name: `${process.env.VM_NAME || 'vm'}/${scanTarget.name}`,
          severity: counter.Severity,
          namespace: process.env.VM_NAME || 'trivy-exporter'
        }, counter.count)
      }
    }
    console.log('Fin de la gauge ImageVulnerabilities')

    if (scanTarget.type === 'image') {
      const imageRef = parseQualifiedName(scanTarget.name)
      const results = report.Results || []
      for (const result of results) {
        const vulnerabilities = result.Vulnerabilities
        for (const vulnerability of vulnerabilities) {
          for (const container of containers.filter(container => container.image === scanTarget.name)) {
            container.name[0] = container.name[0].replace('/', '')
            const v2Scores = Object.values(vulnerability.CVSS).map(item => item.V2Score).filter(score => score !== undefined)
            const v3Scores = Object.values(vulnerability.CVSS).map(item => item.V3Score).filter(score => score !== undefined)
            const allScores = v2Scores.concat(v3Scores)
            const maxScore = Math.max(...allScores)
            console.log('--->', vulnerability.VulnerabilityID, maxScore, allScores, v2Scores, v3Scores)
            gaugeVulnerabilityID.set({
              container_name: container.name,
              severity: vulnerability.Severity,
              image_registry: imageRef.domain || 'index.docker.io',
              image_repository: imageRef.repository,
              image_tag: imageRef.tag,
              namespace: process.env.VM_NAME || 'trivy-exporter',
              vuln_id: vulnerability.VulnerabilityID,
              vuln_score: maxScore,
              vuln_title: vulnerability.Title
            }, 0)
          }
        }
      }
    } else {
      const results = report.Results || []
      for (const result of results) {
        const vulnerabilities = result.Vulnerabilities
        for (const vulnerability of vulnerabilities) {
          const v2Scores = Object.values(vulnerability.CVSS).map(item => item.V2Score).filter(score => score !== undefined)
          const v3Scores = Object.values(vulnerability.CVSS).map(item => item.V3Score).filter(score => score !== undefined)
          const allScores = v2Scores.concat(v3Scores)
          const maxScore = Math.max(...allScores)
          gaugeVulnerabilityID.set({
            container_name: `${process.env.VM_NAME || 'vm'}/${scanTarget.name}`,
            severity: vulnerability.Severity,
            namespace: process.env.VM_NAME || 'trivy-exporter',
            vuln_id: vulnerability.VulnerabilityID,
            vuln_score: maxScore,
            vuln_title: vulnerability.Title
          })
        }
      }
    }
    console.log('Fin de la gauge Vulnerabilities ID')
  }
  await fs.writeFile('data/metrics.txt', await prometheus.register.metrics())
  console.log('All scans have been completed')
}

exports.start = async () => {
  try {
    await fs.mkdir('data')
  } catch (err) {
    if (err.code !== 'EEXIST') throw err
  }
  try {
    await fs.access('data/metrics.txt')
  } catch (err) {
    console.log(err)
    if (err.code !== 'ENOENT') throw err
    await runAllScans()
  }

  await prometheus.start(9000)

  cron.schedule(process.env.CRON_RULE || '0 0 * * * *', async () => {
    try {
      await runAllScans()
    } catch (err) {
      prometheus.internalError('scan', err.message)
    }
  })
}

exports.stop = async () => {
  await prometheus.stop()
}
