import fs from 'node:fs/promises'
import path from 'node:path'
import { spawn } from 'node:child_process'

const skipDirs = process.env.SKIP_DIRS ? process.env.SKIP_DIRS.split(',') : []
skipDirs.push('/var/lib/docker')

const ignoreUnfixed = process.env.IGNORE_UNFIXED === '1' || process.env.IGNORE_UNFIXED?.toLowerCase() === 'true'

const severityFilter = process.env.SEVERITY

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Unknown'

export type SeverityCounts = Partial<Record<Severity, number>>

export async function parseSeverityCounts (report: any): Promise<SeverityCounts> {
  const results = report.Results || []
  const severityCounts: SeverityCounts = {}
  for (const result of results) {
    const vulnerabilities = result.Vulnerabilities || []
    for (const vulnerability of vulnerabilities) {
      const severity: Severity = vulnerability.Severity.charAt(0).toUpperCase() + vulnerability.Severity.slice(1).toLowerCase()
      if (!severityCounts[severity]) severityCounts[severity] = 0
      severityCounts[severity] += 1
    }
  }
  return severityCounts
}

function execScan (type: 'fs' | 'image', name: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const fileName = `./data/reports/${name.replace(/\//g, '_')}-scan-report.json`
    const args = [type, '--scanners', 'vuln', '--cache-dir', 'data/cache', '--format', 'json', '-o', fileName]
    if (ignoreUnfixed) args.push('--ignore-unfixed')
    if (severityFilter) {
      args.push('--severity')
      args.push(severityFilter)
    }
    args.push(name)
    if (type === 'fs' && name === 'rootfs') {
      for (const skipDir of skipDirs) {
        args.push('--skip-dirs')
        args.push(path.join('/webapp/rootfs', skipDir))
      }
    }
    const process = spawn('trivy', args, { stdio: 'inherit' })
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
