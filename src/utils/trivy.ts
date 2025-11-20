import fs from 'node:fs/promises'
import { spawn } from 'node:child_process'

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Unknown'

export type SeverityCounts = Record<Severity, number>

export async function parseSeverityCounts (report: any): Promise<SeverityCounts> {
  const results = report.Results || []
  const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 }
  for (const result of results) {
    const vulnerabilities = result.Vulnerabilities || []
    for (const vulnerability of vulnerabilities) {
      const severity: Severity = vulnerability.Severity.charAt(0).toUpperCase() + vulnerability.Severity.slice(1).toLowerCase()
      severityCounts[severity] += 1
    }
  }
  return severityCounts
}

function execScan (type: 'fs' | 'image', name: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const fileName = `./data/reports/${name.replace(/\//g, '_')}-scan-report.json`
    const process = spawn('trivy', [type, '--scanners', 'vuln', '--cache-dir', 'data/cache', '--format', 'json', '-o', fileName, name], { stdio: 'inherit' })
    process.on('close', (code) => {
      if (code !== 0) return reject(new Error(`Trivy scan failed with code ${code}`))
      resolve(fileName)
    })
  })
}

export async function runScan (type: 'fs' | 'image', name: string) {
  const fileName = await execScan(type, name)
  const reportStr = await fs.readFile(fileName, 'utf-8')
  return JSON.parse(reportStr)
}
