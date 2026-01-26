import fs from 'node:fs/promises'
import path from 'node:path'
import { spawn, execSync } from 'node:child_process'

const skipDirs = process.env.SKIP_DIRS ? process.env.SKIP_DIRS.split(',') : []
skipDirs.push('/var/lib/docker')

const ignoreUnfixed = process.env.IGNORE_UNFIXED === '1' || process.env.IGNORE_UNFIXED?.toLowerCase() === 'true'

const severityFilter = process.env.SEVERITY

// a somewhat hackish way to filter out vulnerabilities linked to old kernels
// waiting for trivy to implement it correctly
// https://github.com/aquasecurity/trivy/issues/3764#issuecomment-1457869338
const currentKernel = execSync("uname -r | cut -d'-' -f1,2").toString().trim()
console.log('detected kernel version', currentKernel)
await fs.writeFile('/tmp/ignore_old_kernels.rego', (await fs.readFile(import.meta.dirname + '/ignore_old_kernels.rego', 'utf-8')).replace('{{current_kernel}}', currentKernel))

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Unknown'

export type SeverityCounts = Record<Severity, number>

export async function parseSeverityCounts (report: any): Promise<SeverityCounts> {
  const results = report.Results || []
  const severityCounts: SeverityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 }
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
    const args = [
      type,
      '--scanners', 'vuln',
      '--cache-dir', 'data/cache',
      '--format', 'json',
      '-o', fileName
    ]
    if (type === 'fs') {
      args.push('--ignore-policy', '/tmp/ignore_old_kernels.rego')
    }
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
    console.log(`spawn: trivy ${args.join(' ')}`)
    const process = spawn('trivy', args, { stdio: 'inherit' })
    process.on('close', (code, signal) => {
      if (code !== 0) return reject(new Error(`Trivy scan failed with code=${code}, signal=${signal}`))
      resolve(fileName)
    })
  })
}

export async function runScan (type: 'fs' | 'image', name: string) {
  const fileName = await execScan(type, name)
  const reportStr = await fs.readFile(fileName, 'utf-8')
  return JSON.parse(reportStr)
}
