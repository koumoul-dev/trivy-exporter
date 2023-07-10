const fs = require('node:fs').promises
const util = require('node:util')
const exec = util.promisify(require('node:child_process').exec)

async function runTrivyScan (imageName) {
  const { stdout, stderr } = await exec('trivy image --format json -o report/' + imageName + '-scan-report' + '.json ' + imageName)
  console.log(`error: ${stderr}`)
  console.log('stdout:', stdout)
  console.log('Scan report has been created')
  const reportStr = await fs.readFile('report/' + imageName + '-scan-report' + '.json', 'utf-8')
  return JSON.parse(reportStr)
}

async function runTrivyScanRoot () {
  const { stdout, stderr } = await exec('trivy fs --format json -o report/root-scan-report.json /')
  console.log(`error: ${stderr}`)
  console.log('stdout:', stdout)
  console.log('Scan report has been created')
  const reportStr = await fs.readFile('report/root-scan-report.json', 'utf-8')
  return JSON.parse(reportStr)
}

module.exports = runTrivyScan
module.exports = runTrivyScanRoot
