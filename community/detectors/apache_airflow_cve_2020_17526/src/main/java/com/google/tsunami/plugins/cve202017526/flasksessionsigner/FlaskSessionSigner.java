package com.google.tsunami.plugins.cve202017526.flasksessionsigner;

import java.util.Base64;

public class FlaskSessionSigner {
  public final String timestamp;
  public String payload;
  public byte[] separator;
  public TokenSigner signer;

  public FlaskSessionSigner(String payload, String timestamp, String secret, String salt) {
    this.separator = new byte[] {(byte) '.'};
    this.payload = payload;
    this.timestamp = timestamp;
    this.signer = new TokenSigner(secret.getBytes(), salt.getBytes(), this.separator);
  }

  public String dumps() {
    byte[] header = Base64.getUrlEncoder().withoutPadding().encode(payload.getBytes());
    String message =
        String.format("%s%s%s", new String(header), new String(this.separator), this.timestamp);
    return new String(signer.sign(message.getBytes()));
  }
}
