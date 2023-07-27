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
  const gauge = prometheus.vulnerabilitiesGauge()

  const scanTargets = [...imageNames.map(name => ({ type: 'image', name })), { type: 'fs', name: 'rootfs' }]
  for (const scanTarget of scanTargets) {
    console.log(`Starting to scan ${scanTarget.type}/${scanTarget.name}`)
    const report = await runTrivyScan(scanTarget.type, scanTarget.name)
    console.log('Scan report', report)

    const counters = await parseCounters(report)
    console.log('Counters', counters)

    for (const counter of counters) {
      if (scanTarget.type === 'image') {
        const imageRef = parseQualifiedName(scanTarget.name)
        for (const container of containers.filter(container => container.image === scanTarget.name)) {
          gauge.set({
            container_name: container.name,
            severity: counter.severity,
            image_registry: imageRef.domain || 'index.docker.io',
            image_repository: imageRef.repository,
            image_tag: imageRef.tag
          }, counter.count)
        }
      } else {
        gauge.set({
          container_name: `${process.env.VM_NAME || 'vm'}/${scanTarget.name}`,
          severity: counter.Severity
        }, counter.count)
      }
    }
  }
  console.log('Metrics', gauge.hashMap)
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
