// code instrumentation to expose metrics for prometheus
// follow this doc for naming conventions https://prometheus.io/docs/practices/naming/
// /metrics serves container/process/pod specific metrics while /global-metrics
// serves metrics for the whole service installation no matter the scaling

import fs from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { Gauge, register } from 'prom-client'

export const vulnerabilitiesGauge = new Gauge({
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

export const vulnerabilitiesIDGauge = new Gauge({
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

export const reset = () => {
  register.resetMetrics()
}

export const store = async () => {
  await fs.writeFile('data/metrics.txt', await register.metrics())
}

let server: Server
export const start = async (port: number) => {
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

export const stop = async () => {
  if (server) server.close()
}
