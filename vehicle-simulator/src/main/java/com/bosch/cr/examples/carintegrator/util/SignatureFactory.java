/*
 * Copyright (c) 2015 Bosch Software Innovations GmbH, Germany. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Bosch Software Innovations GmbH, Germany nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.bosch.cr.examples.carintegrator.util;
 
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
 
/**
 * A factory for signing arbitrary data with the {@value #SIGNATURE_ALGORITHM} algorithm.
 *
 * @since 1.0.0
 */
public final class SignatureFactory
{
 
   /**
    * The algorithm used to generate the key pair.
    */
   public static final String KEY_ALGORITHM = "EC";
 
   /**
    * The algorithm used to sign.
    */
   public static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
 
   private final PrivateKey privateKey;
   private final String publicKeyString;
 
   private SignatureFactory()
   {
      try
      {
         final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
         final KeyPair keyPair = keyPairGenerator.generateKeyPair();
         privateKey = keyPair.getPrivate();
         publicKeyString = createPublicKeyString(keyPair.getPublic());
      }
      catch (final NoSuchAlgorithmException e)
      {
         throw new RuntimeException(e.getCause());
      }
   }
 
   private SignatureFactory(final PrivateKey privateKey, final String publicKeyString)
   {
      this.privateKey = privateKey;
      this.publicKeyString = publicKeyString;
   }
 
   /**
    * Returns a {@code SignatureFactory} instance.
    * <p>
    * Upon creation, a new public and private key pair will be generated by the factory.
    * </p>
    *
    * @return a SignatureFactory instance.
    */
   public static SignatureFactory newInstance()
   {
      return new SignatureFactory();
   }
 
   /**
    * Returns a {@code SignatureFactory} instance for a given private and public key.
    *
    * @param privateKeyString the private key to use in format {@code -----BEGIN PRIVATE KEY-----...}
    * @param publicKeyString the public key to use in format {@code -----BEGIN PUBLIC KEY-----...} or {@code -----BEGIN CERTIFICATE-----...}
    * @return a SignatureFactory instance.
    */
   public static SignatureFactory newInstance(final String privateKeyString, final String publicKeyString)
   {
      return new SignatureFactory(createPrivateKeyFor(privateKeyString), publicKeyString);
   }
 
   /**
    * Returns a {@code SignatureFactory} instance for a given keystore location.
    *
    * @param keystoreUri the keystore location as URI.
    * @param keyStorePassword the keystore's password.
    * @param keyAlias the key's alias.
    * @param keyAliasPassword the key alias' password.
    * @return a SignatureFactory instance.
    */
   public static SignatureFactory newInstance(final URI keystoreUri, final String keyStorePassword,
      final String keyAlias, final String keyAliasPassword)
   {
      try
      {
         final FileInputStream inputStream = new FileInputStream(Paths.get(keystoreUri).toFile());
         final KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
         keystore.load(inputStream, keyStorePassword.toCharArray());
         final Key key = keystore.getKey(keyAlias, keyAliasPassword.toCharArray());
         if (key instanceof PrivateKey)
         {
            // Get certificate of public key
            final Certificate cert = keystore.getCertificate(keyAlias);
 
            // Get public key
            final PublicKey publicKey = cert.getPublicKey();
            return new SignatureFactory((PrivateKey) key, createPublicKeyString(publicKey));
         }
         else
         {
            throw new IllegalStateException("Retrieved key was not a private key");
         }
      }
      catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e)
      {
         throw new IllegalStateException("Could not load private/public keypair from keystore", e);
      }
   }
 
   private static PrivateKey createPrivateKeyFor(final String privateKey)
   {
      try
      {
         String privateKeyPEM = privateKey.replace("\n", "");
         privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----", "");
         privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
         final byte[] decodedBytes = Base64.getDecoder().decode(privateKeyPEM);
         final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedBytes);
         final KeyFactory keyFactory = KeyFactory.getInstance("EC");
         return keyFactory.generatePrivate(keySpec);
      }
      catch (final Exception e)
      {
         throw new RuntimeException(e.getCause());
      }
   }
 
   private static String createPublicKeyString(final PublicKey publicKey)
   {
      final byte[] base64EncodedKey = Base64.getEncoder().encode(publicKey.getEncoded());
      return "-----BEGIN PUBLIC KEY-----" + new String(base64EncodedKey) + "-----END PUBLIC KEY-----";
   }
 
   /**
    * Returns the {@code PublicKey} of this factory in String format.
    *
    * @return the PublicKey.
    */
   public String getPublicKeyString()
   {
      return publicKeyString;
   }
 
   /**
    * Signs the given {@code data} with {@value #SIGNATURE_ALGORITHM}.
    *
    * @param data the data to sign.
    * @return the signed data.
    */
   public String sign(final String data)
   {
      try
      {
         final Signature ecdsa = Signature.getInstance(SIGNATURE_ALGORITHM);
         ecdsa.initSign(privateKey);
         ecdsa.update(data.getBytes());
 
         final byte[] signature = ecdsa.sign();
         final byte[] signatureEncoded = Base64.getEncoder().encode(signature);
 
         return new String(signatureEncoded);
      }
      catch (final Exception e)
      {
         throw new RuntimeException(e.getCause());
      }
   }
}