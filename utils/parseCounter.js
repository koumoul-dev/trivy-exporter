// labelNames: [
//   'container_name',
//   'image_digest',
//   'image_registry',
//   'image_repository',
//   'image_tag',
//   'name',
//   // 'namespace',
//   // 'resource_kind',
//   // 'resource_name',
//   'severity'
// ]

async function parseCounter (report) {
  try {
    const results = report.Results

    const severityCounts = {}

    for (const result of results) {
      const vulnerabilities = result.Vulnerabilities
      for (const vulnerability of vulnerabilities) {
        const severity = vulnerability.Severity

        if (severityCounts[severity]) {
          severityCounts[severity] += 1
        } else {
          severityCounts[severity] = 1
        }
      }
    }

    const gaugeDataArray = Object.entries(severityCounts).map(([severity, count]) => ({
      severity,
      count
    }))

    return gaugeDataArray
  } catch (err) {
    console.error(err)
    throw err // Optionnel : Renvoie l'erreur si nécessaire
  }
}

module.exports = parseCounter
