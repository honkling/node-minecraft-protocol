const uuid = require('uuid-1345')

module.exports = function (client, options) {
  client.once('login', onLogin)

  const mcData = require('minecraft-data')(client.version)

  function onLogin () {
    if (mcData.supportFeature('sessionSignature') && client.profileKeys) {
      client.sessionUUID = uuid.v4fast() // Randomness is irrelevant
      client.write('session', {
        sessionUUID: client.sessionUUID,
        expireTime: BigInt(client.profileKeys.expireTime),
        publicKey: client.profileKeys.publicDER,
        signature: client.profileKeys.signatureV2
      })
    }
  }
}
