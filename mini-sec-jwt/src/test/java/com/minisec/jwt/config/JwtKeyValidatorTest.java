package com.minisec.jwt.config;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtKeyValidatorTest {
    private SecretKey hmacKey(int bits) {
        byte[] bytes = new byte[bits / 8];
        new SecureRandom().nextBytes(bytes);
        String algorithm = switch (bits) {
            case 256 -> "HmacSHA256";
            case 384 -> "HmacSHA384";
            case 512 -> "HmacSHA512";
            default -> "HmacSHA256";
        };
        return new SecretKeySpec(bytes, algorithm);
    }

    private KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        return generator.generateKeyPair();
    }

    private KeyPair ec(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    private KeyPair ed(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EdDSA");
        generator.initialize(new NamedParameterSpec(curve));
        return generator.generateKeyPair();
    }

    @Test
    void rejectsNullAlgorithmAndKey() {
        assertThrows(IllegalArgumentException.class, () -> JwtKeyValidator.validateSigningKey(null, hmacKey(256)));
        assertThrows(IllegalArgumentException.class, () -> JwtKeyValidator.validateVerificationKey(JwtAlgorithm.HS256, null));
    }

    @Test
    void validatesHmacMinimumLengths() {
        assertDoesNotThrow(() -> JwtKeyValidator.validateSigningKey(JwtAlgorithm.HS256, hmacKey(256)));
        assertDoesNotThrow(() -> JwtKeyValidator.validateSigningKey(JwtAlgorithm.HS384, hmacKey(384)));
        assertDoesNotThrow(() -> JwtKeyValidator.validateSigningKey(JwtAlgorithm.HS512, hmacKey(512)));
        assertThrows(IllegalArgumentException.class, () -> JwtKeyValidator.validateSigningKey(JwtAlgorithm.HS512, hmacKey(256)));
    }

    @Test
    void rejectsWrongKeyFamily() throws Exception {
        KeyPair pair = rsa(2048);
        assertThrows(IllegalArgumentException.class, () -> JwtKeyValidator.validateSigningKey(JwtAlgorithm.RS256, pair.getPublic()));
        assertThrows(IllegalArgumentException.class, () -> JwtKeyValidator.validateVerificationKey(JwtAlgorithm.RS256, pair.getPrivate()));
        assertThrows(IllegalArgumentException.class, () -> JwtKeyValidator.validateSigningKey(JwtAlgorithm.HS256, pair.getPrivate()));
    }

    @Test
    void rejectsSmallRsaKeys() throws Exception {
        KeyPair pair = rsa(1024);
        assertThrows(IllegalArgumentException.class, () -> JwtKeyValidator.validateSigningKey(JwtAlgorithm.RS256, pair.getPrivate()));
        assertThrows(IllegalArgumentException.class, () -> JwtKeyValidator.validateVerificationKey(JwtAlgorithm.RS256, pair.getPublic()));
    }

    @Test
    void accepts2048BitRsaKeys() throws Exception {
        KeyPair pair = rsa(2048);
        assertDoesNotThrow(() -> JwtKeyValidator.validateSigningKey(JwtAlgorithm.RS256, pair.getPrivate()));
        assertDoesNotThrow(() -> JwtKeyValidator.validateVerificationKey(JwtAlgorithm.RS256, pair.getPublic()));
    }

    @Test
    void validatesExactEcCurves() throws Exception {
        KeyPair p256 = ec("secp256r1");
        KeyPair p384 = ec("secp384r1");
        KeyPair p521 = ec("secp521r1");

        assertDoesNotThrow(() -> JwtKeyValidator.validateSigningKey(JwtAlgorithm.ES256, p256.getPrivate()));
        assertDoesNotThrow(() -> JwtKeyValidator.validateVerificationKey(JwtAlgorithm.ES384, p384.getPublic()));
        assertDoesNotThrow(() -> JwtKeyValidator.validateSigningKey(JwtAlgorithm.ES512, p521.getPrivate()));

        assertThrows(IllegalArgumentException.class, () -> JwtKeyValidator.validateSigningKey(JwtAlgorithm.ES256, p384.getPrivate()));
        assertThrows(IllegalArgumentException.class, () -> JwtKeyValidator.validateVerificationKey(JwtAlgorithm.ES512, p256.getPublic()));
    }

    @Test
    void acceptsEd25519AndEd448() throws Exception {
        KeyPair ed25519 = ed("Ed25519");
        KeyPair ed448 = ed("Ed448");

        assertDoesNotThrow(() -> JwtKeyValidator.validateSigningKey(JwtAlgorithm.EDDSA, ed25519.getPrivate()));
        assertDoesNotThrow(() -> JwtKeyValidator.validateVerificationKey(JwtAlgorithm.EDDSA, ed25519.getPublic()));
        assertDoesNotThrow(() -> JwtKeyValidator.validateSigningKey(JwtAlgorithm.EDDSA, ed448.getPrivate()));
        assertDoesNotThrow(() -> JwtKeyValidator.validateVerificationKey(JwtAlgorithm.EDDSA, ed448.getPublic()));
    }
}