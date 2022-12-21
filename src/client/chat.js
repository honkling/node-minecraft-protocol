const crypto = require('crypto')
const concat = require('../transforms/binaryStream').concat

const states = {
  SECURE: 0,
  MODIFIED: 1,
  FILTERED: 2,
  NOT_SECURE: 3,
  BROKEN_CHAIN: 4
}

const filter = {
  PASS_THROUGH: 0,
  FULLY_FILTERED: 1,
  PARTIALLY_FILTERED: 2
}

const log = {
  PLAYER_MESSAGE: 0,
  HEADER: 1,
  SYSTEM_MESSAGE: 2
}

const MESSAGE_EXPIRY = 1000 * 60 * 7

module.exports = function (client, options) {
  const mcData = require('minecraft-data')(client.version)

  // Utility functions

  client.signMessage = (message, timestamp, salt = 0n, acknowledgements, isCommand, preview) => {
    if (!client.profileKeys) throw Error("Can't sign message without profile keys, please set valid auth mode")
    if (mcData.supportFeature('chainedSignature')) { // 1.19.1/1.19.2
      const hashable = crypto.createHash('sha256').update(concat('i64', salt, 'i64', timestamp / 1000n, 'pstring', message, 'i8', 70))
      if (preview) hashable.update(Buffer.from(preview, 'utf8'))
      for (const previousMessage of acknowledgements) {
        hashable.update(concat('i8', 70, 'UUID', previousMessage.messageSender))
        hashable.update(Buffer.from(previousMessage.messageSignature))
      }
      const hash = hashable.digest()
      const proto = ['UUID', client.uuid, 'buffer', hash]
      if (!!client.lastSignature && !isCommand) proto.unshift('buffer', client.lastSignature)
      const signable = concat(...proto)
      const signed = crypto.sign('RSA-SHA256', signable, client.profileKeys.private)
      if (!isCommand) client.lastSignature = signed
      return signed
    } else if (mcData.supportFeature('sessionSignature')) { // 1.19.3
      if (!client.sessionUUID) throw Error("Can't sign message before initializing chat session")
      if (!client.sessionIndex) client.sessionIndex = 0
      const length = Buffer.byteLength(message, 'utf8')
      const signable = concat('i32', 1, 'UUID', client.uuid, 'UUID', client.sessionUUID, 'i32', client.sessionIndex, 'i64', salt, 'i64', timestamp / 1000n, 'i32', length, 'pstring', message, 'i32', 0)
      client.sessionIndex++
      return crypto.sign('RSA-SHA256', signable, client.profileKeys.private)
    } else { // 1.19
      const content = preview || JSON.stringify({ text: message })
      const signable = concat('i64', salt, 'UUID', client.uuid, 'i64',
        timestamp / 1000n, 'pstring', content)
      return crypto.sign('RSA-SHA256', signable, client.profileKeys.private)
    }
  }
  client.verifyMessage = (pubKey, packet, session) => {
    if (pubKey instanceof Buffer) pubKey = crypto.createPublicKey({ key: pubKey, format: 'der', type: 'spki' })
    if (mcData.supportFeature('chainedSignature')) { // 1.19.1/1.19.2
      const hashable = crypto.createHash('sha256').update(concat('i64', packet.salt, 'i64', packet.timestamp / 1000n, 'pstring', packet.plainMessage, 'i8', 70))
      if (packet.formattedMessage) hashable.update(Buffer.from(packet.formattedMessage, 'utf8'))
      for (const previousMessage of packet.previousMessages) {
        hashable.update(concat('i8', 70, 'UUID', previousMessage.messageSender))
        hashable.update(Buffer.from(previousMessage.messageSignature))
      }
      const hash = hashable.digest()
      const verifier = crypto.createVerify('RSA-SHA256')
      if (packet.messageSignature) verifier.update(Buffer.from(packet.messageSignature))
      verifier.update(concat('UUID', packet.senderUuid, 'buffer', hash))
      return verifier.verify(pubKey, Buffer.from(packet.headerSignature))
    } else if (mcData.supportFeature('sessionSignature')) { // 1.19.3
      const length = Buffer.byteLength(packet.plainMessage, 'utf8')
      const previousMessages = packet.previousMessages.length > 0 ? ['i32', packet.previousMessages.length, 'buffer', Buffer.concat(...packet.previousMessages.map(msg => msg.signature))] : ['i32', 0]

      const signable = concat('i32', 1, 'UUID', packet.senderUuid, 'UUID', session, 'i32', packet.index, 'i64', packet.salt, 'i64', packet.timestamp / 1000n, 'i32', length, 'pstring', packet.plainMessage, ...previousMessages)
      return crypto.verify('RSA-SHA256', signable, pubKey, packet.messageSignature)
    } else { // 1.19
      const signable = concat('i64', packet.salt, 'UUID', packet.senderUuid,
        'i64', packet.timestamp / 1000n, 'pstring', packet.signedChatContent)
      return crypto.verify('RSA-SHA256', signable, pubKey, packet.signature)
    }
  }
  client.refreshAcknowledgements = () => {
    if (!client.chat_log) return []

    client.chat_log.untracked = 0
    return client.chat_log.acknowledgements
  }

  client.sendMessage = async message => {
    if (message.length > 256) throw Error('Chat message length cannot exceed 256 characters')

    if (mcData.supportFeature('signedChat')) {
      if (mcData.supportFeature('chainedSignature')) {
        const salt = 0n
        const packetData = {
          message,
          salt
        }
        if (client.useChatPreview) {
          try {
            packetData.signedPreview = true
            const preview = await fetchPreview(message)
            const acknowledgements = client.refreshAcknowledgements()
            const timestamp = BigInt(Date.now())
            packetData.timestamp = timestamp
            packetData.signature = client.signMessage(message, timestamp, salt, acknowledgements, false, preview)
            packetData.previousMessages = client.chat_log.acknowledgements
            packetData.lastMessage = client.chat_log ? client.chat_log.lastUntracked : undefined
          } catch {
            // Discard message
          }
        } else {
          packetData.signedPreview = false
          const acknowledgements = client.refreshAcknowledgements()
          const timestamp = BigInt(Date.now())
          packetData.timestamp = timestamp
          packetData.signature = client.signMessage(message, timestamp, salt, acknowledgements)
          packetData.previousMessages = client.chat_log.acknowledgements
          packetData.lastMessage = client.chat_log ? client.chat_log.lastUntracked : undefined
        }

        client.write('chat_message', packetData)
      } else if (mcData.supportFeature('sessionSignature')) {
        // TODO
      } else {
        const timestamp = BigInt(Date.now())
        client.write('chat_message', {
          message,
          timestamp,
          salt: 0n,
          signature: client.signMessage(message, timestamp)
        })
      }
    } else client.write('chat', { message })
  }

  function fetchPreview (message) {
    return new Promise((resolve, reject) => {
      if (client.pendingPreview) {
        if (options.queueMessages) queueMessagePreview(message, resolve, reject)
        else reject(Error('Message could not be sent. Preview already in progress'))
      } else {
        requestPreview(message, resolve, reject)
      }
    })
  }

  function requestPreview (message, resolve, reject) {
    client.previewId = client.previewId || 0
    const id = client.previewId++
    client.pendingPreview = { id, resolve, reject }

    if (!client.lastPreviewRequest) client.lastPreviewRequest = 0
    const diff = Date.now() - client.lastPreviewRequest

    function sendPacket () {
      client.write('chat_preview', {
        query: id,
        message
      })

      if (options.timeoutPreview) {
        client.previewTimeout = setTimeout(() => {
          throw Error('Server did not respond with preview in time') // Probably should not throw
        }, options.timeoutPreview)
      }
    }

    if (diff < 100) {
      setTimeout(sendPacket, diff + 1)
    } else sendPacket()
  }

  function queueMessagePreview (message, resolve, reject) {
    if (!client.previewQueue) client.previewQueue = []
    client.previewQueue.push({ message, resolve, reject })
  }

  // Packet handling

  client.on('chat_preview', handleChatPreview)

  client.on('player_info', handlePlayerInfo)

  client.on('player_chat', handlePlayerChat)

  client.on('system_chat', handleSystemChat)

  client.on('message_header', handleChatHeader)

  client.on('should_display_chat_preview', packet => {
    client.useChatPreview = packet.should_display_chat_preview
  })

  client.on('server_data', packet => {
    client.useChatPreview = packet.previewsChat
    client.signedChat = packet.enforcesSecureChat
  })

  function handleChatPreview (packet) {
    if (packet.queryId === client.pendingPreview.id) {
      setTimeout(() => {
        client.pendingPreview.resolve(packet.message)
      }, 200) // Previews are invalid for the first 200 milliseconds

      if (client.previewTimeout) clearTimeout(client.previewTimeout)
      if (options.queueMessages && !!client.previewQueue) {
        const next = client.previewQueue.splice(0, 1)
        if (next) requestPreview(next.message, next.resolve, next.reject)
      }
    }
  }

  function handlePlayerInfo (packet) {
    if (mcData.supportFeature('playerInfoActionsIsBitfield')) { // 1.19.3

    } else { // 1.19.2 and earlier
      if (packet.action === 0) { // add player
        if (!client.players) client.players = {}
        packet.data.forEach(player => {
          client.players[player.UUID] = player.crypto
        })
      } else if (packet.action === 4) { // remove player
        packet.data.forEach(player => {
          if (!client.players || !client.players[player.UUID]) return
          delete client.players[player.UUID]
        })
      }
    }
  }

  function handlePlayerChat (packet) {
    if (!client.signedChat) return // Don't attempt to validate messages when chat signing is disabled

    const state = getSecureState(packet)

    if (state === states.BROKEN_CHAIN) throw Error('Chat validation failed')

    let tracked = true

    if (state === states.NOT_SECURE && options.secureChatOnly) tracked = false
    if (packet.filterType === filter.FULLY_FILTERED) tracked = false

    logMessage(packet, tracked)
    if (tracked) client.emit('chat_validated', packet)
  }

  function handleSystemChat (packet) {
    if (!client.signedChat) return // Don't log messages when chat signing is disabled
    if (packet.isActionBar) return // Don't log action bar messages

    logSystemMessage(packet)
  }

  function handleChatHeader (packet) {
    if (!client.signedChat) return // Don't attempt to validate messages when chat signing is disabled

    const state = validateHeader(packet)

    if (state === states.BROKEN_CHAIN) throw Error('Chat validation failed')

    logHeader(packet)
  }

  function getSecureState (packet) {
    if (!client.players[packet.senderUuid] || !client.players[packet.senderUuid].publicKey) return states.NOT_SECURE

    const state = validateMessage(packet)

    if (state === states.BROKEN_CHAIN) return states.BROKEN_CHAIN
    if (BigInt(Date.now()) - packet.timestamp > MESSAGE_EXPIRY) return states.NOT_SECURE
    if (packet.filterType !== filter.PASS_THROUGH) return states.FILTERED
    if (packet.unsignedContent !== undefined) return states.MODIFIED
    return states.SECURE
  }

  function validateMessage (packet) {
    const messageSignature = packet.messageSignature ? Buffer.from(packet.messageSignature) : undefined
    const headerSignature = Buffer.from(packet.headerSignature)

    if (mcData.supportFeature('chainedSignature') && !validateChain(packet, messageSignature, headerSignature, true)) return states.BROKEN_CHAIN
    if (mcData.supportFeature('sessionSignature') && !validateSession(packet)) return states.BROKEN_CHAIN

    const valid = client.verifyMessage(client.players[packet.senderUuid].publicKey, packet, mcData.supportFeature('sessionSignature') ? client.players[packet.senderUuid].uuid : undefined)

    if (!valid) return states.BROKEN_CHAIN

    client.players[packet.senderUuid].lastSignature = headerSignature
    return states.SECURE
  }

  function validateHeader (packet) {
    if (!client.players[packet.senderUuid] || !client.players[packet.senderUuid].publicKey) return states.NOT_SECURE

    const messageSignature = packet.messageSignature ? Buffer.from(packet.messageSignature) : undefined
    const headerSignature = Buffer.from(packet.headerSignature)

    if (!validateChain(packet, messageSignature, headerSignature, false)) return states.BROKEN_CHAIN

    const verifier = crypto.createVerify('RSA-SHA256')
    if (messageSignature) verifier.update(messageSignature)
    verifier.update(concat('UUID', packet.senderUuid, 'buffer', packet.bodyDigest))
    return verifier.verify(client.players[packet.senderUuid].publicKey, headerSignature) ? states.SECURE : states.BROKEN_CHAIN
  }

  function validateChain (packet, signature, header, full) {
    const lastSignature = client.players[packet.senderUuid].lastSignature

    if (!packet.headerSignature || packet.headerSignature.length === 0) return false
    if (full && !!signature && !!lastSignature && lastSignature.compare(signature) === 0) return true
    return lastSignature === undefined || lastSignature.compare(header) === 0
  }

  function validateSession (packet) {
    return false
  }

  function logSystemMessage (packet) {
    if (!client.chat_log) {
      client.chat_log = {
        log: [],
        old: 0,
        new: 0,
        untracked: 0,
        acknowledgements: []
      }
    }

    const id = client.chat_log.new++
    if (id >= 1024) client.chat_log.old++

    client.chat_log.log[id % 1024] = { type: log.SYSTEM_MESSAGE, packet, timestamp: Date.now() }
  }

  function logHeader (packet) {
    if (!client.chat_log) {
      client.chat_log = {
        log: [],
        old: 0,
        new: 0,
        untracked: 0,
        acknowledgements: []
      }
    }

    const id = client.chat_log.new++
    if (id >= 1024) client.chat_log.old++

    client.chat_log.log[id % 1024] = { type: log.HEADER, packet }
  }

  function logMessage (packet, tracked) {
    if (!client.chat_log) {
      client.chat_log = {
        log: [],
        old: 0,
        new: 0,
        untracked: 0,
        acknowledgements: []
      }
    }
    if (tracked) {
      const id = client.chat_log.new++
      if (id >= 1024) client.chat_log.old++

      client.chat_log.log[id % 1024] = { type: log.PLAYER_MESSAGE, packet }

      if (!client.chat_log.acknowledgements.some(message => message.messageSender === packet.senderUuid)) {
        client.chat_log.acknowledgements.unshift({
          messageSender: packet.senderUuid, messageSignature: packet.headerSignature
        })
        client.chat_log.acknowledgements.length = Math.min(client.chat_log.acknowledgements.length, 5)
      }
      client.chat_log.lastUntracked = undefined
    } else client.chat_log.lastUntracked = { sender: packet.senderUuid, signature: packet.headerSignature }
    if (client.chat_log.untracked++ > 64) sendAcknowledgements()
  }

  function sendAcknowledgements () {
    if (!client.chat_log) return
    const acknowledgements = client.refreshAcknowledgements()

    client.write('message_acknowledgement', {
      previousMessages: acknowledgements,
      lastMessage: client.chat_log.lastUntracked
    })
  }
}
