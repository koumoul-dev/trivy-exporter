// Import for testing
const assert = require('assert').strict

// Import function to be tested
// const { after, it, afterEach, before } = require('mocha')

describe('Trivy exporter', () => {
  describe('Trivy scan', () => {
    before(async () => {
    })

    afterEach(async () => {
    })

    // Do a test execute mkdir comma,nd when report folder does not exist
    // it('should list images of running containers', async () => {
    //   const getImageNames = require('../utils/getImageNames')
    //   const imageNames = await getImageNames()
    //   console.log(imageNames)

    //   assert.ok(imageNames.includes('alpine:3.17.0'))
    // })

    // it('should run Trivy scan', async () => {
    //   const runTrivyScan = require('../utils/runTrivyScan')
    //   const imageName = 'alpine:3.17.0'
    //   const result = await runTrivyScan(imageName)
    //   const vulnerabilities = result.Results[0].Vulnerabilities

    //   assert.ok(vulnerabilities.length > 0)
    //   assert.ok(vulnerabilities[0].VulnerabilityID.startsWith('CVE-'))
    // 
    // it('should run all scans', async () => {
    //   const appTest = require('../app')
    //   await appTest.start()
    // })

    it('should run Trivy scan root', async () => {
      const runTrivyScanRoot = require('../utils/runTrivyScan')
      const result = await runTrivyScanRoot()
      console.log(result)
    })
  })
})
