/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.ratchet;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.kdf.DerivedRootSecrets;
import org.whispersystems.libsignal.kdf.HKDF;
import org.whispersystems.libsignal.util.ByteUtil;
import org.whispersystems.libsignal.util.Pair;
import org.whispersystems.libsignal.util.Triplet;

public class AuthKey {

  private final HKDF   kdf;
  private final byte[] key;

  public AuthKey(HKDF kdf, byte[] key) {
    this.kdf = kdf;
    this.key = key;
  }

  public byte[] getKeyBytes() {
    return key;
  }

  public Triplet<RootKey, ChainKey, AuthKey> createChain(ECPublicKey theirRatchetKey, ECKeyPair ourRatchetKey)
      throws InvalidKeyException
  {
    byte[]             sharedSecret       = Curve.calculateAgreement(theirRatchetKey, ourRatchetKey.getPrivateKey());
    byte[]             derivedSecretBytes = kdf.deriveSecrets(sharedSecret, key, "WhisperRatchet".getBytes(), DerivedRootSecrets.SIZE);
    DerivedRootSecrets derivedSecrets     = new DerivedRootSecrets(derivedSecretBytes);

    RootKey  newRootKey  = new RootKey(kdf, derivedSecrets.getRootKey());
    ChainKey newChainKey = new ChainKey(kdf, derivedSecrets.getChainKey(), 0);
    AuthKey newAuthKey = new AuthKey(kdf, derivedSecrets.getAuthKey());
    //create new triplet class

    return new Triplet<>(newRootKey, newChainKey, newAuthKey);
  }
}
