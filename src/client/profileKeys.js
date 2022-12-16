const Https = require('https')
const crypto = require('crypto')

function makePrivateKey (data) {
  let pem = '-----BEGIN PRIVATE KEY-----\n'
  const suf = '-----END PRIVATE KEY-----\n'
  let raw = data.split('\n').slice(1, -2).join('')
  while (raw.length > 0) {
    pem += raw.substring(0, 65) + '\n'
    raw = raw.substring(65)
  }

  return crypto.createPrivateKey(pem + suf)
}

function makePublicKey (data) {
  let pem = '-----BEGIN PUBLIC KEY-----\n'
  const suf = '-----END PUBLIC KEY-----\n'
  let raw = data.split('\n').slice(1, -2).join('')
  while (raw.length > 0) {
    pem += raw.substring(0, 65) + '\n'
    raw = raw.substring(65)
  }

  return crypto.createPublicKey(pem + suf)
}

module.exports = function (client, options) {
  if (!options.accessToken) throw new Error('Invalid user access token')
  return new Promise((resolve, reject) => {
    const req = Https.request('https://api.minecraftservices.com/player/certificates', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${options.accessToken}`
      }
    }, res => {
      res.setEncoding('utf8')
      let builder = ''
      res.on('data', chunk => {
        builder += chunk
      })

      res.on('end', () => {
        if (res.statusCode >= 300) client.emit('error', new Error(`HTTP Error ${res.statusCode}. Response body ${builder}`))
        else {
          try {
            const data = JSON.parse(builder)
            client.profileKeys = {
              public: makePublicKey(data.keyPair.publicKey),
              private: makePrivateKey(data.keyPair.privateKey),
              signature: Buffer.from(data.publicKeySignature, 'base64'),
              signaturev2: Buffer.from(data.publicKeySignatureV2, 'base64'),
              expireTime: Date.parse(data.expiresAt)
            }
            client.profileKeys.publicDER = Buffer.from(data.keyPair.publicKey.split('\n').slice(1, -2).join(''), 'base64')
            resolve()
          } catch (error) {
            client.emit('error', error)
          }
        }
      })
    })

    req.on('error', error => {
      client.emit('error', error)
    })
    req.end()
  })
}
