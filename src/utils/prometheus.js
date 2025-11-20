// code instrumentation to expose metrics for prometheus
// follow this doc for naming conventions https://prometheus.io/docs/practices/naming/
// /metrics serves container/process/pod specific metrics while /global-metrics
// serves metrics for the whole service installation no matter the scaling

const fs = require('node:fs/promises')
const { createServer } = require('node:http')
const { Gauge, register } = require('prom-client')

exports.vulnerabilitiesGauge = new Gauge({
  name: 'trivy_image_vulnerabilities',
  help: 'Trivy image vulnerabilities',
  labelNames: [
    'container_name',
    'image_registry',
    'image_repository',
    'image_tag',
    // 'name',
    'namespace',
    // 'resource_kind',
    // 'resource_name',
    'severity'
  ]
})

exports.vulnerabilitiesIDGauge = new Gauge({
  name: 'trivy_vulnerability_id',
  help: 'Trivy vulnerability ID',
  labelNames: [
    'container_name',
    'image_registry',
    'image_repository',
    'image_tag',
    // 'name',
    'namespace',
    // 'resource_kind',
    // 'resource_name',
    'severity',
    'vuln_id',
    'vuln_score',
    'vuln_title'
  ]
})

exports.reset = () => {
  register.resetMetrics()
}

exports.register = register

let server
exports.start = async (port) => {
  server = createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/metrics') {
      fs.readFile('data/metrics.txt', 'utf8')
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
