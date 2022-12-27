const lastSeenStates = {
  REMOVED_MESSAGES: 0,
  OUT_OF_ORDER: 1,
  UNKNOWN_MESSAGES: 2,
  DUPLICATED_PROFILES: 3
}

module.exports = function (client, server, options) {
  const raise = (translatableError) => client.end(translatableError, JSON.stringify({ translate: translatableError }))
  const throwGeneric = (message) => client.end(message, JSON.stringify({ translate: 'disconnect.genericReason', with: [{ text: message }] }))

  const {
    'enable-chat-signing': signedChat
  } = options

  client.on('chat_message', handleChatMessage)

  client.lastMessage = {
    timestamp: 0
  }

  function handleChatMessage (packet) {
    if (!signedChat) return // Don't validate messages when chat signing is disabled

    if (!isLegal(packet.message)) {
      raise('multiplayer.disconnect.illegal_characters')
    }

    if (packet.timestamp < client.lastMessage.timestamp) {
      raise('multiplayer.disconnect.out_of_order_chat')
      return
    }

    client.lastMessage.timestamp = packet.timestamp

    // TODO: Handle chat filtering

    if (packet.previousMessages.length > 5) {
      throwGeneric('Invalid packet format') // TODO: Match Java exception format?
      return
    }
    const errors = validateLastSeen(packet)

    if (errors.length > 0) {
      raise('multiplayer.disconnect.chat_validation_failed')
      return
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

    const valid = client.verifyMessage(packet)
    if (!valid) {
      raise('multiplayer.disconnect.unsigned_chat')
    }

    // Chat message validated (1.19.2)
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

  function isLegal (message) {
    for (let i = 0; i < message.length; i++) {
      const char = message.charCodeAt(i)
      if (char < 32 || char === 167 || char === 127) return false
    }
    return true
  }
}
