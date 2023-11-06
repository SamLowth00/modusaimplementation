/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.kdf;

import org.whispersystems.libsignal.util.ByteUtil;

public class DerivedRootSecrets {

  public static final int SIZE = 96;

  private final byte[] rootKey;
  private final byte[] chainKey;
  private final byte[] authKey;

  public DerivedRootSecrets(byte[] okm) {
    byte[][] keys = ByteUtil.split(okm, 32, 64);
    this.rootKey  = keys[0];
    byte[][] keys2 = ByteUtil.split(keys[1],32, 32);
    this.chainKey = keys2[0];
    this.authKey = keys2[1];
    //this.authKey = keys[2];
    //System.out.println("TEST >>>"+keys);
  }

  public byte[] getRootKey() {
    return rootKey;
  }

  public byte[] getChainKey() {
    return chainKey;
  }
  public byte[] getAuthKey() {
    return authKey;
  }

}
