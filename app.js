const fs = require('node:fs/promises')
const getImageNames = require('./utils/getImageNames')
const runTrivyScan = require('./utils/runTrivyScan')
const prometheus = require('./utils/prometheus')
const parseCounter = require('./utils/parseCounter')
const cron = require('node-cron')

const runAllScans = async () => {
  console.log('run all scans')
  const imageNames = await getImageNames()
  const gauge = prometheus.vulnerabilitiesGauge()

  for (const imageName of imageNames) {
    console.log('Starting to scan ' + imageName)
    const report = await runTrivyScan(imageName)
    console.log('Scan report', report)

    const counter = await parseCounter(report)
    console.log('Counter', counter)

    for (const result of report.Results) {
      const vulnerabilities = result.Vulnerabilities
      for (const vulnerability of vulnerabilities) {
        const severity = vulnerability.Severity
        const count = counter.find((item) => item.severity === severity)?.count || 0

        gauge.set({ container_name: report.ArtifactName, severity: vulnerability.Severity }, count)
      }
    }
  }
  console.log('Metrics', gauge.hashMap)
  console.log('All scans have been completed')
}

exports.start = async () => {
  try {
    await fs.mkdir('report')
  } catch (err) {
    if (err.code !== 'EEXIST') throw err
  }
  await runAllScans()
  await prometheus.start(9000)

  cron.schedule('0 * * * * * *', async () => {
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
