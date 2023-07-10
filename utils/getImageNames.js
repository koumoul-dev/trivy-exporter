const http = require('http')

async function getImageNames () {
  return new Promise((resolve, reject) => {
    // Options de la requête
    const options = {
      socketPath: '/var/run/docker.sock',
      path: '/containers/json',
      method: 'GET'
    }

    // Envoyer la requête HTTP
    const req = http.request(options, (res) => {
      let data = ''

      // Recevoir les données de réponse
      res.on('data', (chunk) => {
        data += chunk
      })

      // Fin de la réponse
      res.on('end', () => {
        // console.log('Réponse de la requête :', data)
        // Analyser la réponse JSON
        const containers = JSON.parse(data)

        // Extraire les noms d'image
        const imageNames = [...new Set(containers.map((container) => container.Image))]
        // console.log(imageNames)

        resolve(imageNames)

        // Si nous souhaitons le nom de toutes les images et le nombre
        // let i = 0;
        // console.log("There is/are " + imageNames.length + " image(s) that is/are :");
        // while(i < imageNames.length) {
        //   console.log(imageNames[i]);
        //   i++;
        // };
      })
    })

    // Gérer les erreurs de requête
    req.on('error', (error) => {
      console.error('Erreur lors de la requête :', error)
      reject(error)
    })

    // Terminer la requête
    req.end()
  })
}

module.exports = getImageNames
