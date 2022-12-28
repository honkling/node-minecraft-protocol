const UUID = require('uuid-1345')
const crypto = require('crypto')
const pluginChannels = require('../client/pluginChannels')
const states = require('../states')
const yggdrasil = require('yggdrasil')
const { concat } = require('../transforms/binaryStream')
const { mojangPublicKeyPem } = require('./constants')

module.exports = function (client, server, options) {
  const mojangPubKey = crypto.createPublicKey(mojangPublicKeyPem)
  const raise = (translatableError) => client.end(translatableError, JSON.stringify({ translate: translatableError }))
  const yggdrasilServer = yggdrasil.server({ agent: options.agent })
  const {
    'online-mode': onlineMode = true,
    kickTimeout = 30 * 1000,
    errorHandler: clientErrorHandler = (client, err) => client.end(err)
  } = options

  let serverId
  const mcData = require('minecraft-data')(client.version)

  client.on('error', function (err) {
    clientErrorHandler(client, err)
  })
  client.on('end', () => {
    clearTimeout(loginKickTimer)
  })
  client.once('login_start', onLogin)

  function kickForNotLoggingIn () {
    client.end('LoginTimeout')
  }
  let loginKickTimer = setTimeout(kickForNotLoggingIn, kickTimeout)

  function onLogin (packet) {
    client.username = packet.username
    const isException = !!server.onlineModeExceptions[client.username.toLowerCase()]
    const needToVerify = (onlineMode && !isException) || (!onlineMode && isException)

    if (mcData.supportFeature('signatureEncryption')) {
      if (options.enforceSecureProfile && !packet.signature) { // TODO: Don't enforce this check in 1.19.3
        raise('multiplayer.disconnect.missing_public_key')
        return
      }
    }
    if (packet.signature) {
      if (packet.signature.timestamp < BigInt(Date.now())) {
        raise('multiplayer.disconnect.invalid_public_key_signature')
        return // expired tokens, client needs to restart game
      }

      try {
        const publicKey = crypto.createPublicKey({ key: packet.signature.publicKey, format: 'der', type: 'spki' })
        const publicDER = publicKey.export({ type: 'spki', format: 'der' })
        const publicPEM = mcPubKeyToPem(publicDER)
        if (mcData.supportFeature('profileKeySignatureV2')) {
          if (!packet.playerUUID) {
            client.end('Invalid packet format', JSON.stringify({ translate: 'disconnect.genericReason', with: [{ text: 'Invalid packet format' }] }))
            return
          }

          if (!crypto.verify('RSA-SHA1', concat('UUID', packet.playerUUID, 'i64', packet.signature.timestamp, 'buffer', publicDER), mojangPubKey, packet.signature.signature)) {
            raise('multiplayer.disconnect.invalid_public_key_signature')
            return
          }
          client.profileKeys = { public: publicKey, publicPEM }
        } else {
          const signable = packet.signature.timestamp + publicPEM // (expires at + publicKey)
          if (!crypto.verify('RSA-SHA1', Buffer.from(signable, 'ascii'), mojangPubKey, packet.signature.signature)) {
            raise('multiplayer.disconnect.invalid_public_key_signature')
            return
          }
          client.profileKeys = { public: publicKey, publicPEM }
        }
      } catch (err) {
        raise('multiplayer.disconnect.invalid_public_key')
        return
      }
    }

    if (needToVerify) {
      serverId = crypto.randomBytes(4).toString('hex')
      client.verifyToken = crypto.randomBytes(4)
      const publicKeyStrArr = server.serverKey.exportKey('pkcs8-public-pem').split('\n')
      let publicKeyStr = ''
      for (let i = 1; i < publicKeyStrArr.length - 1; i++) {
        publicKeyStr += publicKeyStrArr[i]
      }
      client.publicKey = Buffer.from(publicKeyStr, 'base64')
      client.once('encryption_begin', onEncryptionKeyResponse)
      client.write('encryption_begin', {
        serverId,
        publicKey: client.publicKey,
        verifyToken: client.verifyToken
      })
    } else {
      loginClient()
    }
  }

  function onEncryptionKeyResponse (packet) {
    if (client.profileKeys) {
      if (options.enforceSecureProfile && packet.hasVerifyToken) {
        raise('multiplayer.disconnect.missing_public_key')
        return // Unexpected - client has profile keys, and we expect secure profile
      }
    }

    if (packet.hasVerifyToken === false) {
      // 1.19, hasVerifyToken is set and equal to false IF chat signing is enabled
      // This is the default action starting in 1.19.1.
      const signable = concat('buffer', client.verifyToken, 'i64', packet.crypto.salt)
      if (!crypto.verify('sha256WithRSAEncryption', signable, client.profileKeys.public, packet.crypto.messageSignature)) {
        raise('multiplayer.disconnect.invalid_public_key_signature')
        return
      }
    } else {
      const encryptedToken = packet.hasVerifyToken ? packet.crypto.verifyToken : packet.verifyToken
      try {
        const decryptedToken = crypto.privateDecrypt({
          key: server.serverKey.exportKey(),
          padding: crypto.constants.RSA_PKCS1_PADDING
        }, encryptedToken)

        if (!client.verifyToken.equals(decryptedToken)) {
          client.end('DidNotEncryptVerifyTokenProperly')
          return
        }
      } catch {
        client.end('DidNotEncryptVerifyTokenProperly')
        return
      }
    }

    let sharedSecret
    try {
      sharedSecret = crypto.privateDecrypt({
        key: server.serverKey.exportKey(),
        padding: crypto.constants.RSA_PKCS1_PADDING
      }, packet.sharedSecret)
    } catch (e) {
      client.end('DidNotEncryptVerifyTokenProperly')
      return
    }

    client.setEncryption(sharedSecret)

    const isException = !!server.onlineModeExceptions[client.username.toLowerCase()]
    const needToVerify = (onlineMode && !isException) || (!onlineMode && isException)
    const nextStep = needToVerify ? verifyUsername : loginClient
    nextStep()

    function verifyUsername () {
      yggdrasilServer.hasJoined(client.username, serverId, sharedSecret, client.publicKey, function (err, profile) {
        if (err) {
          client.end('Failed to verify username!')
          return
        }

        // Convert to a valid UUID until the session server updates and does
        // it automatically
        client.uuid = profile.id.replace(/(\w{8})(\w{4})(\w{4})(\w{4})(\w{12})/, '$1-$2-$3-$4-$5')
        client.username = profile.name
        client.profile = profile
        loginClient()
      })
    }
  }

  // https://github.com/openjdk-mirror/jdk7u-jdk/blob/f4d80957e89a19a29bb9f9807d2a28351ed7f7df/src/share/classes/java/util/UUID.java#L163
  function javaUUID (s) {
    const hash = crypto.createHash('md5')
    hash.update(s, 'utf8')
    const buffer = hash.digest()
    buffer[6] = (buffer[6] & 0x0f) | 0x30
    buffer[8] = (buffer[8] & 0x3f) | 0x80
    return buffer
  }

  function nameToMcOfflineUUID (name) {
    return (new UUID(javaUUID('OfflinePlayer:' + name))).toString()
  }

  function loginClient () {
    const isException = !!server.onlineModeExceptions[client.username.toLowerCase()]
    if (onlineMode === false || isException) {
      client.uuid = nameToMcOfflineUUID(client.username)
    }
    options.beforeLogin?.(client)
    if (client.protocolVersion >= 27) { // 14w28a (27) added whole-protocol compression (http://wiki.vg/Protocol_History#14w28a), earlier versions per-packet compressed TODO: refactor into minecraft-data
      client.write('compress', { threshold: 256 }) // Default threshold is 256
      client.compressionThreshold = 256
    }
    client.write('success', {
      uuid: client.uuid,
      username: client.username,
      properties: []
    })
    // TODO: find out what properties are on 'success' packet
    client.state = states.PLAY

    clearTimeout(loginKickTimer)
    loginKickTimer = null

    server.playerCount += 1
    client.once('end', function () {
      server.playerCount -= 1
    })
    pluginChannels(client, options)

    if (client.profileKeys) {
      client.verifyMessage = (packet, acknowledgements) => {
        if (mcData.supportFeature('chainedSignature')) { // 1.19.1/1.19.2
          const hashable = crypto.createHash('sha256').update(concat('i64', packet.salt, 'i64', packet.timestamp / 1000n, 'pstring', packet.message, 'i8', 70))
          if (packet.signedPreview) hashable.update(Buffer.from(client.createPreview(packet.message), 'utf8')) // TODO: Implement chat previews
          for (const previousMessage of packet.previousMessages) {
            hashable.update(concat('i8', 70, 'UUID', previousMessage.messageSender))
            hashable.update(Buffer.from(previousMessage.messageSignature))
          }
          const hash = hashable.digest()
          const verifier = crypto.createVerify('RSA-SHA256')
          if (client.previousSignature) verifier.update(client.previousSignature)
          verifier.update(concat('UUID', client.uuid, 'buffer', hash))
          return verifier.verify(client.profileKeys.public, packet.signature)
        } else { // 1.19
          const signable = concat('i64', packet.salt, 'UUID', client.uuid, 'i64', packet.timestamp / 1000n, 'pstring', JSON.stringify({ text: packet.message }))
          return crypto.verify('RSA-SHA256', signable, client.profileKeys.public, packet.signature)
        }
      }
    }
    server.emit('login', client)
  }
}

function mcPubKeyToPem (mcPubKeyBuffer) {
  let pem = '-----BEGIN RSA PUBLIC KEY-----\n'
  let base64PubKey = mcPubKeyBuffer.toString('base64')
  const maxLineLength = 76
  while (base64PubKey.length > 0) {
    pem += base64PubKey.substring(0, maxLineLength) + '\n'
    base64PubKey = base64PubKey.substring(maxLineLength)
  }
  pem += '-----END RSA PUBLIC KEY-----\n'
  return pem
}
