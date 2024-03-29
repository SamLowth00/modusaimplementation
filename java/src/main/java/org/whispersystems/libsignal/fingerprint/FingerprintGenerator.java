/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.fingerprint;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.ratchet.AuthKey;

import java.util.List;

public interface FingerprintGenerator {
  public Fingerprint createFor(int version,
                               byte[] localStableIdentifier,
                               IdentityKey localIdentityKey,
                               byte[] remoteStableIdentifier,
                               IdentityKey remoteIdentityKey, AuthKey authenticationKey, byte[] sessionHash);

  public Fingerprint createFor(int version,
                               byte[] localStableIdentifier,
                               List<IdentityKey> localIdentityKey,
                               byte[] remoteStableIdentifier,
                               List<IdentityKey> remoteIdentityKey, AuthKey authenticationKey, byte[] sessionHash);
}
