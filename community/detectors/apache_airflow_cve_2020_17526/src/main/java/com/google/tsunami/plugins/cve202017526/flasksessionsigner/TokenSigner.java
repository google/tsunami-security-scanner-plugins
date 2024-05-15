package com.google.tsunami.plugins.cve202017526.flasksessionsigner;

import com.google.common.primitives.Bytes;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TokenSigner implements Cloneable {
  public String digestMethod;
  public byte[] secret_key;
  public byte[] salt;
  public byte[] sep;

  public TokenSigner(byte[] secret_key, byte[] salt, byte[] sep) {
    this.digestMethod = "HmacSHA1";
    this.secret_key = secret_key;
    this.salt = salt;
    this.sep = sep;
  }

  public byte[] derive_key() throws Exception {
    try {
      SecretKeySpec signingKey = new SecretKeySpec(secret_key, digestMethod);
      Mac mac = Mac.getInstance(digestMethod);
      mac.init(signingKey);
      return mac.doFinal(salt);
    } catch (NoSuchAlgorithmException e) {
      throw new Exception("No such derivation algorithm");
    } catch (InvalidKeyException e) {
      throw new Exception("Invalid derivation key");
    }
  }

  public byte[] get_signature(byte[] value) {
    try {
      byte[] key = derive_key();
      SecretKeySpec signingKey = new SecretKeySpec(key, digestMethod);
      Mac mac = Mac.getInstance(digestMethod);
      mac.init(signingKey);
      byte[] sig = mac.doFinal(value);
      return Base64.getUrlEncoder().withoutPadding().encode(sig);
    } catch (Exception e) {
      return new byte[] {};
    }
  }

  public byte[] sign(byte[] value) {
    return Bytes.concat(value, sep, get_signature(value));
  }

  public TokenSigner clone() {
    try {
      return (TokenSigner) super.clone();
    } catch (CloneNotSupportedException e) {
      throw new AssertionError();
    }
  }
}
