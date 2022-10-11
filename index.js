const assert = require('assert');
const { BitGo, Eddsa, generateGPGKeyPair, EDDSAUtils, getBitgoGpgPubKey } = require('bitgo');
const openpgp = require('openpgp');

const accessToken = require('./accessToken');

const bitgo = new BitGo({ env: 'test' });
const coin = 'tsol';

async function main() {
  bitgo.authenticateWithAccessToken({ accessToken });

  const MPC = await Eddsa.initialize();
  const m = 2;
  const n = 3;

  const userKeyShare = MPC.keyShare(1, m, n);
  const backupKeyShare = MPC.keyShare(2, m, n);

  const userGpgKeySerialized = await generateGPGKeyPair('secp256k1');
  const userGpgKey = await openpgp.readKey({ armoredKey: userGpgKeySerialized.privateKey });
  const userGpgKeyId = Buffer.from(userGpgKey.keyPacket.fingerprint).toString('hex').padStart(40, '0')

  console.log('gpg key created');

  const MpcUtils = EDDSAUtils.default;
  const mpcUtils = new MpcUtils(bitgo, bitgo.coin(coin));
  const bitgoKeychain = await mpcUtils.createBitgoKeychain(userGpgKeySerialized, userKeyShare, backupKeyShare);

  console.log('bitgo keychain created');

  const bitgoPub = await getBitgoGpgPubKey(bitgo);
  const walletSigs = await openpgp.readKeys({ armoredKeys: bitgoKeychain.walletHSMGPGPublicKeySigs });
  assert(walletSigs.length === 2, 'walletSigs should have length 2');

  const walletSigUser = walletSigs[0];
  const isValidsUser = await walletSigUser.verifyPrimaryUser([bitgoPub]);
  console.log(`is valids user: ${JSON.stringify(isValidsUser)}`); // expected one of the values to have a `valid` key set to a truthy value

  const walletSigBackup = walletSigs[1];
  const isValidsBackup = await walletSigBackup.verifyPrimaryUser([bitgoPub]);
  console.log(`is valids backup: ${JSON.stringify(isValidsBackup)}`);

  const primaryUser = await walletSigUser.getPrimaryUser();

  assert(primaryUser.user.otherCertifications[0].rawNotations.length === 5, 'invalid wallet signatures');

  assert(
    bitgoKeychain.commonKeychain === Buffer.from(primaryUser.user.otherCertifications[0].rawNotations[0].value).toString(),
    'wallet signature does not match common keychain',
  );
  assert(
    userGpgKeyId ===
    Buffer.from(primaryUser.user.otherCertifications[0].rawNotations[1].value).toString().padStart(40, '0'),
    'wallet signature does not match user key id',
  );
  // normally the backup gpg key id, but here we use one gpg key for both user and backup
  assert(
    userGpgKeyId ===
    Buffer.from(primaryUser.user.otherCertifications[0].rawNotations[2].value).toString().padStart(40, '0'),
    'wallet signature does not match backup key id',
  );
}

main().catch((e) => {
  console.log(e);
});
