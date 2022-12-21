const states = require('../states')
const crypto = require('crypto')
const concat = require('../transforms/binaryStream').concat

module.exports = function (client, options) {
  client.once('success', onLogin)

  const mcData = require('minecraft-data')(client.version)

  function onLogin (packet) {
    client.signedChat = true
    client.state = states.PLAY
    client.uuid = packet.uuid
    client.username = packet.username
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
        if (!!packet.messageSignature) verifier.update(Buffer.from(packet.messageSignature))
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
    },
    client.refreshAcknowledgements = () => {
      if(!client.chat_log) return []

      client.chat_log.untracked = 0
      return client.chat_log.acknowledgements
    }
  }
}
