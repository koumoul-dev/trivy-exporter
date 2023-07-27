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

async function parseCounters (report) {
  try {
    const results = report.Results || []
    const severityCounts = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Unknown: 0
    }

    for (const result of results) {
      const vulnerabilities = result.Vulnerabilities
      for (const vulnerability of vulnerabilities) {
        const severity = vulnerability.Severity.charAt(0).toUpperCase() + vulnerability.Severity.slice(1).toLowerCase()

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

module.exports = parseCounters
