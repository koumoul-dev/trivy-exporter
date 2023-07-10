// code instrumentation to expose metrics for prometheus
// follow this doc for naming conventions https://prometheus.io/docs/practices/naming/
// /metrics serves container/process/pod specific metrics while /global-metrics
// serves metrics for the whole service installation no matter the scaling

const { createServer } = require('node:http')
const { Counter, Gauge, register } = require('prom-client')

// local metrics incremented throughout the code
const internalErrorCounter = new Counter({
  name: 'df_internal_error',
  help: 'A counter of errors from any service, worker, etc. Do not use for client errors, only for anomalies that should trigger alerts. Each increment should be accompanied by an error log with matching code.',
  labelNames: ['errorCode']
})

exports.internalError = (errorCode, message, ...optionalParams) => {
  internalErrorCounter.inc({ errorCode })
  console.error(`[${errorCode}] ${message}`, ...optionalParams)
}

exports.vulnerabilitiesGauge = () => {
  register.removeSingleMetric('trivy_image_vulnerabilities')
  return new Gauge({
    name: 'trivy_image_vulnerabilities',
    help: 'Trivy image vulnerabilities',
    labelNames: [
      'container_name',
      'image_digest',
      'image_registry',
      'image_repository',
      'image_tag',
      'name',
      // 'namespace',
      // 'resource_kind',
      // 'resource_name',
      'severity'
    ]
  })
}

let server
exports.start = async (port) => {
  server = createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/metrics') {
      register.metrics()
        .then(metrics => {
          res.setHeader('Content-Type', register.contentType)
          res.writeHead(200)
          res.write(metrics)
          res.end()
        })
        .catch(err => {
          console.error('failed to server prometheus /metrics', err)
          res.writeHead(500)
          res.end()
        })
    } else {
      res.writeHead(404)
      res.end()
    }
  })
  server.listen(port)
  await new Promise(resolve => server.once('listening', resolve))
  console.log(`Prometheus metrics server available on http://localhost:${port}/metrics`)
}

exports.stop = async () => {
  if (server) server.close()
}
