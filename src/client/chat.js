const crypto = require('crypto')

const states = {
    "SECURE": 0,
    "MODIFIED": 1,
    "FILTERED": 2,
    "NOT_SECURE": 3,
    "BROKEN_CHAIN": 4
}

const filter = {
    "PASS_THROUGH": 0,
    "FULLY_FILTERED": 1,
    "PARTIALLY_FILTERED": 2
}

const log = {
    "PLAYER_MESSAGE": 0,
    "HEADER": 1,
    "SYSTEM_MESSAGE": 2
}

const MESSAGE_EXPIRY = 1000 * 60 * 7;

module.exports = function (client, options) {
    const mcData = require('minecraft-data')(client.version);

    client.on('player_info', handlePlayerInfo)

    client.on('player_chat', handlePlayerChat)

    client.on('system_chat', handleSystemChat)

    client.on('message_header', handleChatHeader)

    function handlePlayerInfo(packet) {
        if(mcData.supportFeature('multipleActionsPlayerInfo')) { // 1.19.3

        } else { // 1.19.2 and earlier
            if(packet.action == 0) { // add player
                if(!client.players) client.players = {}
                packet.data.forEach(player => client.players[player.UUID] = player.crypto)
            } else if(packet.action == 4) { // remove player
                if(!client.players || !client.players[player.UUID]) return
                delete client.players[player.UUID]
            }
        }
    }

    function handlePlayerChat(packet) {
        if(!client.signedChat) return // Don't attempt to validate messages when chat signing is disabled

        const state = getSecureState(packet)

        if(state == states.BROKEN_CHAIN) throw Error('Chat validation failed')

        let tracked = true

        if(state == states.NOT_SECURE && options.secureChatOnly) tracked = false
        if(packet.filterType == filter.FULLY_FILTERED) tracked = false

        logMessage(packet, tracked)
        if(tracked) client.emit('chat_validated', packet)
    }

    function handleSystemChat(packet) {
        if(!client.signedChat) return // Don't log messages when chat signing is disabled
        if(packet.isActionBar) return // Don't log action bar messages

        logSystemMessage()
    }

    function handleChatHeader(packet) {
        if(!client.signedChat) return // Don't attempt to validate messages when chat signing is disabled

        const state = validateHeader(packet)

        if(state == states.BROKEN_CHAIN) throw Error('Chat validation failed')

        logHeader(packet)
    }

    function getSecureState(packet) {
        if(!client.players[packet.senderUuid] || !client.players[packet.senderUuid].publicKey) return states.NOT_SECURE

        const state = validateMessage(packet)

        if(state == states.BROKEN_CHAIN) return states.BROKEN_CHAIN
        if(BigInt(Date.now()) - packet.timestamp > MESSAGE_EXPIRY) return states.NOT_SECURE
        if(packet.filterType !== filter.PASS_THROUGH) return states.FILTERED
        if(packet.unsignedContent !== undefined) return states.MODIFIED
        return states.SECURE
    }

    function validateMessage(packet) {
        const messageSignature = packet.messageSignature ? Buffer.from(packet.messageSignature) : undefined
        const headerSignature = Buffer.from(packet.headerSignature)

        if(mcData.supportFeature('chainedSignature') && !validateChain(packet, messageSignature, headerSignature, true)) return states.BROKEN_CHAIN
        if(mcData.supportFeature('sessionSignature') && !validateSession(packet)) return states.BROKEN_CHAIN

        const valid = client.verifyMessage(client.players[packet.senderUuid].publicKey, packet, mcData.supportFeature('sessionSignature') ? client.players[packet.senderUuid].uuid : undefined);

        if(!valid) return states.BROKEN_CHAIN
        
        client.players[packet.senderUuid].lastSignature = headerSignature
        return states.SECURE
    }

    function validateHeader(packet) {
        if(!client.players[packet.senderUuid] || !client.players[packet.senderUuid].publicKey) return states.NOT_SECURE

        const messageSignature = packet.messageSignature ? Buffer.from(packet.messageSignature) : undefined
        const headerSignature = Buffer.from(packet.headerSignature)

        if(!validateChain(packet, messageSignature, headerSignature, false)) return states.BROKEN_CHAIN

        const verifier = crypto.createVerify('RSA-SHA256')
        if(!!messageSignature) verifier.update(messageSignature)
        verifier.update(concat('UUID', packet.senderUuid, 'buffer', packet.bodyDigest))
        return verifier.verify(client.players[packet.senderUuid].publicKey, headerSignature) ? states.SECURE : states.BROKEN_CHAIN
    }

    function validateChain(packet, signature, header, full) {
        const lastSignature = client.players[packet.senderUuid].lastSignature

        if(!packet.headerSignature || packet.headerSignature.length == 0) return false
        if(full && !!signature && !!lastSignature && lastSignature.compare(signature) == 0) return true
        return lastSignature == null || lastSignature.compare(header) == 0
    }

    function validateSession(packet) {
        return false
    }

    function logSystemMessage(packet) {
        if(!client.chat_log) client.chat_log = {
            log: [],
            old: 0,
            new: 0,
            untracked: 0,
            acknowledgements: []
        }

        const id = client.chat_log.new++
        if(id >= 1024) client.chat_log.old++

        client.chat_log.log[id % 1024] = {type: log.SYSTEM_MESSAGE, packet: packet, timestamp: Date.now()}
    }

    function logHeader(packet) {
        if(!client.chat_log) client.chat_log = {
            log: [],
            old: 0,
            new: 0,
            untracked: 0,
            acknowledgements: []
        }

        const id = client.chat_log.new++
        if(id >= 1024) client.chat_log.old++

        client.chat_log.log[id % 1024] = {type: log.HEADER, packet: packet}
    }

    function logMessage(packet, tracked) {
        if(!client.chat_log) client.chat_log = {
            log: [],
            old: 0,
            new: 0,
            untracked: 0,
            acknowledgements: []
        }
        if(tracked) {
            const id = client.chat_log.new++
            if(id >= 1024) client.chat_log.old++

            client.chat_log.log[id % 1024] = {type: log.PLAYER_MESSAGE, packet: packet}

            if(!client.chat_log.acknowledgements.some(message => message.messageSender == packet.senderUuid)) {
                client.chat_log.acknowledgements.unshift({
                    messageSender: packet.senderUuid, messageSignature: packet.headerSignature
                })
                client.chat_log.acknowledgements.length = Math.min(client.chat_log.acknowledgements.length, 5)
            }
            client.chat_log.lastUntracked = undefined
        } else client.chat_log.lastUntracked = { sender: packet.senderUuid, signature: packet.headerSignature }
        if(client.chat_log.untracked++ > 64) sendAcknowledgements()
    }

    function sendAcknowledgements() {
        if(!client.chat_log) return
        const acknowledgements = client.refreshAcknowledgements()

        client.write('message_acknowledgement', {
            previousMessages: acknowledgements,
            lastMessage: client.chat_log.lastUntracked
        })
    }
}