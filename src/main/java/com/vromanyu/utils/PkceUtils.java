package com.vromanyu.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public final class PkceUtils {

    /**
     * @param size random bytes size. Must be between 32 and 64.
     * @return code verifier as Base64 URL encoded string
     * @implNote uses SecureRandom to generate the random bytes.
     */
 public static String generateCodeVerifier(int size) {
  if (size < 32 || size > 64) {
   throw new IllegalArgumentException("size must be between 32 and 64");
  }
  SecureRandom secureRandom = new SecureRandom();
  byte[] verifier = new byte[size];
  secureRandom.nextBytes(verifier);
  return Base64.getUrlEncoder().withoutPadding().encodeToString(verifier);
 }

    /**
     * @param codeVerifier The generated code verifier.
     * @return code challenge as Base64 URL encoded string
     * @throws NoSuchAlgorithmException if SHA-256 algorithm is not supported
     * @implNote gets the ASCII encoded bytes of the code verifier and hashes them using SHA-256.
     */
 public static String generateCodeChallenge(String codeVerifier) throws NoSuchAlgorithmException {
  if (codeVerifier == null) {
   throw new IllegalArgumentException("code verifier must not be null");
  }
  byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
  MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
  messageDigest.update(bytes, 0, bytes.length);
  byte[] digest = messageDigest.digest();
  return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
 }
}
