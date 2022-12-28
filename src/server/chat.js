const { mojangPublicKeyPem } = require('./constants')
const crypto = require('crypto')
const { concat } = require('../transforms/binaryStream')

const lastSeenStates = {
  REMOVED_MESSAGES: 0,
  OUT_OF_ORDER: 1,
  UNKNOWN_MESSAGES: 2,
  DUPLICATED_PROFILES: 3
}

const chatVisibility = {
  FULL: 0,
  SYSTEM: 1,
  HIDDEN: 2
}

module.exports = function (client, server, options) {
  const mojangPubKey = crypto.createPublicKey(mojangPublicKeyPem)
  const mcData = require('minecraft-data')(client.version)
  const raise = (translatableError) => client.end(translatableError, JSON.stringify({ translate: translatableError }))
  const throwGeneric = (message) => client.end(message, JSON.stringify({ translate: 'disconnect.genericReason', with: [{ text: message }] }))

  const {
    'enable-chat-signing': signedChat
  } = options

  client.on('chat_message', handleChatMessage)

  client.on('settings', handleClientSettings)

  client.on('player_chat', handleIncomingChat) // Do server-side clients emit this event?

  client.on('message_acknowledgement', handleAcknowledgements)

  client.on('chat_session', handleChatSession)

  client.lastMessage = {
    timestamp: 0
  }

  client.packAcknowledgements = (acknowledgements) => {
    if (!client.signature_cache) client.signature_cache = []

    return acknowledgements.map(ack => {
      const idx = client.signature_cache.findIndex(el => el.compare(ack) === 0)
      if (idx === -1) return { id: 0, signature: ack }
      return { id: idx }
    })
  }

  function handleChatSession (packet) {
    const publicKey = crypto.createPublicKey({ key: packet.publicKey.keyBytes, format: 'der', type: 'spki' })
    const publicPEM = mcPubKeyToPem(packet.publicKey.keyBytes)

    client.session = {
      uuid: packet.uuid,
      index: 0
    }

    const signable = packet.signature.timestamp + publicPEM // (expires at + publicKey)

    if (!crypto.verify('RSA-SHA1', concat('UUID', client.uuid, 'buffer', Buffer.from(signable, 'utf8')), mojangPubKey, packet.publicKey.signature)) {
      raise('multiplayer.disconnect.invalid_public_key_signature')
      return
    }
    if (!client.profileKeys) {
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
          verifier.update(concat('UUID', packet.senderUuid, 'buffer', hash))
          return verifier.verify(client.profileKeys.public, packet.signature)
        } else if (mcData.supportFeature('sessionSignature')) { // 1.19.3
          const length = Buffer.byteLength(packet.message, 'utf8')
          const previousMessages = acknowledgements.length > 0 ? ['i32', acknowledgements.length, 'buffer', Buffer.concat(...acknowledgements)] : ['i32', 0]

          const signable = concat('i32', 1, 'UUID', client.uuid, 'UUID', client.session.uuid, 'i32', client.session.index, 'i64', packet.salt, 'i64', packet.timestamp / 1000n, 'i32', length, 'pstring', packet.message, ...previousMessages)
          return crypto.verify('RSA-SHA256', signable, client.profileKeys.public, packet.messageSignature)
        } else { // 1.19
          const signable = concat('i64', packet.salt, 'UUID', packet.senderUuid,
            'i64', packet.timestamp / 1000n, 'pstring', packet.signedChatContent)
          return crypto.verify('RSA-SHA256', signable, client.profileKeys.public, packet.signature)
        }
      }
    }
    client.profileKeys = { public: publicKey, publicPEM }
  }

  function handleClientSettings (packet) {
    client.chatVisibility = packet.chatFlags
  }

  function handleIncomingChat (packet) {
    if (mcData.supportFeature('sessionSignature') && !!packet.messageSignature) {
      addPendingMessage({ signature: packet.messageSignature })

      if (!client.signature_cache) client.signature_cache = []

      const signatures = []
      packet.previousMessages.forEach(message => {
        if (message.signature) signatures.push(message.signature)
        else if (client.signature_cache[message.id]) signatures.push(client.signature_cache[message.id])
      })

      signatures.push(packet.messageSignature)
      const uniqueSignatures = new Set(signatures)

      for (let i = 0; signatures.length > 0 && i < 128; i++) {
        const currentSignature = client.signature_cache[i]
        client.signature_cache[i] = signatures.splice(-1, 1)[0]
        if (!!currentSignature && !uniqueSignatures.has(currentSignature)) signatures.unshift(currentSignature)
      }
    } else if (mcData.supportFeature('chainedSignature') && !!packet.headerSignature) addPendingMessage({ messageSignature: packet.headerSignature, messageSender: packet.senderUuid })
  }

  function handleAcknowledgements (packet) {
    if (mcData.supportFeature('sessionSignature')) {
      if (!client.previousMessages) client.previousMessages = new Array(20).fill(null)

      if (packet.offset < 0 || packet.offset > (client.previousMessages.length - 20)) {
        raise('multiplayer.disconnect.chat_validation_failed')
        return
      }

      client.previousMessages = client.previousMessages.splice(0, packet.offset)
    } else if (mcData.supportFeature('chainedSignature')) {
      const errors = validateLastSeen(packet)

      if (errors.length > 0) {
        raise('multiplayer.disconnect.chat_validation_failed')
      }
    }
  }

  function handleChatMessage (packet) {
    if (!signedChat) return // Don't validate messages when chat signing is disabled

    if (!client.profileKeys) return // Not sure how to handle this situation currently

    if (!isLegal(packet.message)) {
      raise('multiplayer.disconnect.illegal_characters')
    }

    if (packet.timestamp < client.lastMessage.timestamp) {
      raise('multiplayer.disconnect.out_of_order_chat')
      return
    }

    client.lastMessage.timestamp = packet.timestamp

    if (client.chatVisibility === chatVisibility.HIDDEN) {
      client.write('system_chat', {
        content: JSON.stringify({
          translate: 'chat.disabled.options',
          color: 'red'
        }),
        isActionBar: false
      })
      return
    }

    let ack

    if (mcData.supportFeature('chainedSignature')) {
      if (packet.previousMessages.length > 5) {
        throwGeneric('Invalid packet format') // TODO: Match Java exception format?
        return
      }
      const errors = validateLastSeen(packet)

      if (errors.length > 0) {
        raise('multiplayer.disconnect.chat_validation_failed')
        return
      }
    } else if (mcData.supportFeature('sessionSignature')) {
      const { valid, acknowledgements } = getAcknowledgements(packet)
      ack = acknowledgements

      if (!valid) {
        raise('multiplayer.disconnect.chat_validation_failed')
        return
      }
    }

    if (client.profileKeys.expireTime < Date.now()) {
      client.write('system_chat', {
        content: JSON.stringify({
          translate: 'chat.disabled.expiredProfileKey',
          color: 'red'
        }),
        isActionBar: false
      })
      return
    }

    const valid = client.verifyMessage(packet, ack)
    if (!valid) {
      raise('multiplayer.disconnect.unsigned_chat')
    }

    if (mcData.supportFeature('chainedSignature')) client.previousSignature = packet.signature

    // Chat message validated
  }

  function getAcknowledgements (packet) {
    const acknowledgements = []

    if (!client.previousMessages) client.previousMessages = new Array(20).fill(null)

    if (packet.offset < 0 || packet.offset > (client.previousMessages.length - 20)) return { valid: false, acknowledgements }

    client.previousMessages = client.previousMessages.splice(0, packet.offset)

    const bitset = packet.acknowledged[0] | (packet.acknowledged[1] << 8) | (packet.acknowledged[2] << 16)

    let cardinality
    let t = bitset

    for (cardinality = 0; t > 0; cardinality++) t &= t - 1

    for (let i = 0; i < 20; i++) {
      const set = bitset & (1 << i) !== 0
      const tracked = client.previousMessages[i]

      if (set) {
        if (tracked === null) return { valid: false, acknowledgements }

        client.previousMessages[i].pending = false
        acknowledgements.push(tracked.signature)
      } else {
        if (tracked !== null && !tracked.pending) return { valid: false, acknowledgements }

        client.previousMessages[i] = null
      }
    }
    return { valid: true, acknowledgements }
  }

  function validateLastSeen (packet) {
    const errors = new Set()
    const lastSeen = packet.previousMessages
    const lastReceived = packet.lastMessage

    if (!client.previousMessages) client.previousMessages = []

    if (lastSeen.length < client.previousMessages.length) errors.add(lastSeenStates.REMOVED_MESSAGES)

    let lastIndex = -1
    lastSeen.forEach(seen => {
      const idx = client.previousMessages.findIndex(rec => Buffer.from(rec.messageSignature).compare(Buffer.from(seen.messageSignature)) === 0 && rec.messageSender === seen.messageSender && !rec.pending)

      if (idx < 0) errors.add(lastSeenStates.UNKNOWN_MESSAGES)
      else if (idx < lastIndex) errors.add(lastSeenStates.OUT_OF_ORDER)
      else lastIndex = idx
    })

    if (lastReceived) {
      const idx = client.previousMessages.findIndex(rec => Buffer.from(rec.messageSignature).compare(Buffer.from(lastReceived.signature)) === 0 && rec.messageSender === lastReceived.sender && rec.pending)

      if (idx < 0 || idx < lastIndex) errors.add(lastSeenStates.UNKNOWN_MESSAGES)
      else {
        client.previousMessages = client.previousMessages.filter(message => !message.pending || idx > lastIndex)
      }
    }

    const checker = lastSeen.reduce((acc, message) => {
      acc.add(message.messageSender)
      return acc
    }, new Set())
    if (checker.size < lastSeen.length) errors.add(lastSeenStates.DUPLICATED_PROFILES)

    client.previousMessages = packet.previousMessages
    return errors
  }

  function addPendingMessage (record) {
    client.previousMessages.push({ pending: true, ...record })

    if (client.previousMessages.length > 4096) raise('multiplayer.disconnect.too_many_pending_chats')
  }

  function isLegal (message) {
    for (let i = 0; i < message.length; i++) {
      const char = message.charCodeAt(i)
      if (char < 32 || char === 167 || char === 127) return false
    }
    return true
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
