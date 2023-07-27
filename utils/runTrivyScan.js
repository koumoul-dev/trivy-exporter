const fs = require('node:fs').promises
const util = require('node:util')
const exec = util.promisify(require('node:child_process').exec)

async function runTrivyScan (type, name) {
  console.log(`-> Enter runTrivyScan with type=${type} and name=${name}`)
  const { stdout, stderr } = await exec(`trivy ${type} --format json -o ./data/${name}-scan-report.json ${name}`)
  console.log('-> After exec')
  console.log(`error: ${stderr}`)
  console.log('stdout:', stdout)
  console.log('Scan report has been created')
  const reportStr = await fs.readFile(`./data/${name}-scan-report.json`, 'utf-8')
  return JSON.parse(reportStr)
}

module.exports = runTrivyScan
