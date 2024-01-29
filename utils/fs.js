const fs = require('node:fs/promises')

exports.ensureDir = async (dir) => {
  try {
    await fs.mkdir(dir)
  } catch (err) {
    if (err.code !== 'EEXIST') throw err
  }
}

exports.emptyDir = async (dir) => {
  await this.ensureDir(dir)
  const files = await fs.readdir(dir)
  for (const file of files) {
    await fs.unlink(`${dir}/${file}`)
  }
}

exports.fileExists = async (file) => {
  try {
    await fs.access(file)
  } catch (err) {
    if (err.code === 'ENOENT') return false
    throw err
  }
  return true
}
