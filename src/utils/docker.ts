import http from 'node:http'

export type ContainerRef = {
  name: string,
  image: string
}

const prepareContainerName = (name: string) => {
  if (name.startsWith('/')) return name.replace('/', '')
  return name
}

export async function getContainers (): Promise<ContainerRef[]> {
  return new Promise((resolve, reject) => {
    const options = {
      socketPath: '/var/run/docker.sock',
      path: '/containers/json',
      method: 'GET'
    }

    // Envoyer la requête HTTP
    const req = http.request(options, (res) => {
      let data = ''
      res.on('data', (chunk) => { data += chunk })

      res.on('end', () => {
        const containers: any[] = JSON.parse(data)
        resolve(containers.map(container => ({ name: prepareContainerName(container.Names[0]), image: container.Image })))
      })
    })

    req.on('error', (error) => { reject(error) })

    req.end()
  })
}
