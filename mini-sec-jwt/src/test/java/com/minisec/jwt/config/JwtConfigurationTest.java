package com.minisec.jwt.config;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class JwtConfigurationTest {
    private SecretKey key() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return new SecretKeySpec(bytes, "HmacSHA256");
    }

    @Test
    void createsValidConfiguration() {
        JwtConfiguration config = new JwtConfiguration(JwtAlgorithm.HS256, key(), "sub", "authorities");
        assertEquals(JwtAlgorithm.HS256, config.algorithm());
        assertEquals("sub", config.principalClaim());
        assertEquals("authorities", config.authoritiesClaim());
    }

    @Test
    void rejectsNullAlgorithmAndKey() {
        assertThrows(NullPointerException.class, () -> new JwtConfiguration(null, key(), "sub", "authorities"));
        assertThrows(NullPointerException.class, () -> new JwtConfiguration(JwtAlgorithm.HS256, null, "sub", "authorities"));
    }

    @Test
    void rejectsBlankClaimNames() {
        assertThrows(IllegalArgumentException.class, () -> new JwtConfiguration(JwtAlgorithm.HS256, key(), " ", "authorities"));
        assertThrows(IllegalArgumentException.class, () -> new JwtConfiguration(JwtAlgorithm.HS256, key(), "sub", ""));
    }

    @Test
    void rejectsDuplicateClaimNames() {
        assertThrows(IllegalArgumentException.class, () -> new JwtConfiguration(JwtAlgorithm.HS256, key(), "sub", "sub"));
    }

    @Test
    void rejectsReservedClaimNames() {
        assertThrows(IllegalArgumentException.class, () -> new JwtConfiguration(JwtAlgorithm.HS256, key(), "iat", "authorities"));
        assertThrows(IllegalArgumentException.class, () -> new JwtConfiguration(JwtAlgorithm.HS256, key(), "sub", "exp"));
        assertThrows(IllegalArgumentException.class, () -> new JwtConfiguration(JwtAlgorithm.HS256, key(), "nbf", "authorities"));
    }
}