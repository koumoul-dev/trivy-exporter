const fs = require('node:fs').promises
const { spawn } = require('node:child_process')

const execScan = (type, name) => {
  return new Promise((resolve, reject) => {
    const fileName = `./data/reports/${name.replace(/\//g, '_')}-scan-report.json`
    const process = spawn('trivy', [type, '--scanners', 'vuln', '--cache-dir', 'data/cache', '--format', 'json', '-o', fileName, name], { stdio: 'inherit' })
    process.on('close', (code) => {
      console.log(`child process exited with code ${code}`)
      if (code !== 0) return reject(new Error(`Trivy scan failed with code ${code}`))
      resolve(fileName)
    })
  })
}

async function runTrivyScan (type, name) {
  const fileName = await execScan(type, name)
  console.log('Scan report has been created')
  const reportStr = await fs.readFile(fileName, 'utf-8')
  return JSON.parse(reportStr)
}

module.exports = runTrivyScan
