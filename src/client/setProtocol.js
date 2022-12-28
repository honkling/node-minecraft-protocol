'use strict'

const states = require('../states')

module.exports = function (client, options) {
  const mcData = require('minecraft-data')(client.version)
  client.on('connect', onConnect)

  function onConnect () {
    if (client.wait_connect) {
      client.on('connect_allowed', next)
    } else {
      next()
    }

    function next () {
      let taggedHost = options.host
      if (client.tagHost) taggedHost += client.tagHost
      if (options.fakeHost) taggedHost = options.fakeHost

      client.write('set_protocol', {
        protocolVersion: options.protocolVersion,
        serverHost: taggedHost,
        serverPort: options.port,
        nextState: 2
      })
      client.state = states.LOGIN

      client.write('login_start', {
        username: client.username,
        playerUUID: mcData.supportFeature('signatureOnLogin') ? client.uuid : undefined,
        signature: (mcData.supportFeature('signatureOnLogin') && client.profileKeys)
          ? {
              timestamp: BigInt(client.profileKeys.expireTime),
              publicKey: client.profileKeys.publicDER,
              signature: mcData.supportFeature('profileKeySignatureV2') ? client.profileKeys.signatureV2 : client.profileKeys.signature
            }
          : undefined
      })
    }
  }
}
