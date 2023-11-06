/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.fingerprint;

import org.whispersystems.libsignal.ratchet.RatchetingSession;

import org.whispersystems.libsignal.state.SessionState;
import org.whispersystems.libsignal.ratchet.AuthKey;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.util.ByteUtil;
import org.whispersystems.libsignal.util.IdentityKeyComparator;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class NumericFingerprintGenerator implements FingerprintGenerator {

  private static final int FINGERPRINT_VERSION = 0;
  private final int iterations;
  //private final SessionState sessionState;

  /**
   * Construct a fingerprint generator for 60 digit numerics.
   *
   * @param iterations The number of internal iterations to perform in the process of
   *                   generating a fingerprint. This needs to be constant, and synchronized
   *                   across all clients.
   *
   *                   The higher the iteration count, the higher the security level:
   *
   *                   - 1024 ~ 109.7 bits
   *                   - 1400 > 110 bits
   *                   - 5200 > 112 bits
   */
  public NumericFingerprintGenerator(int iterations) {
    this.iterations = iterations;
  }

  /**
   * Generate a scannable and displayable fingerprint.
   *
   * @param version The version of fingerprint you are generating.
   * @param localStableIdentifier The client's "stable" identifier.
   * @param localIdentityKey The client's identity key.
   * @param remoteStableIdentifier The remote party's "stable" identifier.
   * @param remoteIdentityKey The remote party's identity key.
   * @return A unique fingerprint for this conversation.
   */
  @Override
  public Fingerprint createFor(int version,
                               byte[] localStableIdentifier,
                               final IdentityKey localIdentityKey,
                               byte[] remoteStableIdentifier,
                               final IdentityKey remoteIdentityKey, final AuthKey authenticationKey, final byte[] sessionHash)
  {
    return createFor(version,
                     localStableIdentifier,
                     new LinkedList<IdentityKey>() {{
                       add(localIdentityKey);
                     }},
                     remoteStableIdentifier,
                     new LinkedList<IdentityKey>() {{
                       add(remoteIdentityKey);
                     }}, authenticationKey, sessionHash);
  }

  /**
   * Generate a scannable and displayable fingerprint for logical identities that have multiple
   * physical keys.
   *
   * Do not trust the output of this unless you've been through the device consistency process
   * for the provided localIdentityKeys.
   *
   * @param version The version of fingerprint you are generating.
   * @param localStableIdentifier The client's "stable" identifier.
   * @param localIdentityKeys The client's collection of physical identity keys.
   * @param remoteStableIdentifier The remote party's "stable" identifier.
   * @param remoteIdentityKeys The remote party's collection of physical identity key.
   * @return A unique fingerprint for this conversation.
   */
  public Fingerprint createFor(int version,
                               byte[] localStableIdentifier,
                               List<IdentityKey> localIdentityKeys,
                               byte[] remoteStableIdentifier,
                               List<IdentityKey> remoteIdentityKeys, AuthKey authenticationKey, byte[] sessionHash)
  {
    //byte[] authKey = sessionState.getAuthKey().getKeyBytes();
    byte[] authKey = authenticationKey.getKeyBytes();
    byte[] localFingerprint  = getFingerprint(iterations, localStableIdentifier, localIdentityKeys, authKey, sessionHash);
    byte[] remoteFingerprint = getFingerprint(iterations, remoteStableIdentifier, remoteIdentityKeys, authKey, sessionHash);

    DisplayableFingerprint displayableFingerprint = new DisplayableFingerprint(localFingerprint,
                                                                               remoteFingerprint);

    ScannableFingerprint   scannableFingerprint   = new ScannableFingerprint(version,
                                                                             localFingerprint,
                                                                             remoteFingerprint);

    return new Fingerprint(displayableFingerprint, scannableFingerprint);
  }
//1. edit signiture of getFingerprint to add authkey + chain hash
  private byte[] getFingerprint(int iterations, byte[] stableIdentifier, List<IdentityKey> unsortedIdentityKeys, byte[] authKey, byte[] sessionHash) {
    try {
      //byte[] sessionHash =  SessionState.getSessionHash();

      //byte [] thisAuthKey = authKey.getKeyBytes();
      MessageDigest digest    = MessageDigest.getInstance("SHA-512");
      byte[]        publicKey = getLogicalKeyBytes(unsortedIdentityKeys);
      byte[]        hash      = ByteUtil.combine(ByteUtil.shortToByteArray(FINGERPRINT_VERSION),
                                                 publicKey, stableIdentifier);
      //try do this in session state or somewhere else
      //byte[]        sessionHash = ByteUtil.combine(ByteUtil.shortToByteArray(FINGERPRINT_VERSION),
                                                 //publicKey, stableIdentifier);
      //digest.update(sessionHash);
      //sessionHash = digest.digest(publicKey);

      //for (int i=0;i<iterations;i++) {
        //digest.update(hash);
        //hash = digest.digest(publicKey);
      //}
      Mac mac = Mac.getInstance("HmacSHA256");
      //insert authkey from session state
      mac.init(new SecretKeySpec(authKey, "HmacSHA256"));
      //insert value of chain hash from session state
      return (mac.doFinal(sessionHash));
      //return hash;
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
    //} catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  private byte[] getLogicalKeyBytes(List<IdentityKey> identityKeys) {
    ArrayList<IdentityKey> sortedIdentityKeys = new ArrayList<>(identityKeys);
    Collections.sort(sortedIdentityKeys, new IdentityKeyComparator());

    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    for (IdentityKey identityKey : sortedIdentityKeys) {
      byte[] publicKeyBytes = identityKey.getPublicKey().serialize();
      baos.write(publicKeyBytes, 0, publicKeyBytes.length);
    }

    return baos.toByteArray();
  }


}
