const fs = require('node:fs').promises
const util = require('node:util')
const exec = util.promisify(require('node:child_process').exec)

async function runTrivyScan (type, name) {
  console.log(`-> Enter runTrivyScan with type=${type} and name=${name}`)
  const fileName = `./data/${name.replace(/\//g, '_')}-scan-report.json`
  await exec(`trivy ${type} --format json -o ${fileName} ${name}`)
  console.log('Scan report has been created')
  const reportStr = await fs.readFile(fileName, 'utf-8')
  return JSON.parse(reportStr)
}

module.exports = runTrivyScan
