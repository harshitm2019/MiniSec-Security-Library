package com.minisec.jwt.jjwt;

import com.minisec.core.authentication.Authentication;
import com.minisec.jwt.JwtClaims;
import com.minisec.jwt.JwtTokenService;
import com.minisec.jwt.config.JwtAlgorithm;
import com.minisec.jwt.config.JwtConfiguration;
import com.minisec.jwt.exception.JwtAuthenticationException;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JjwtJwtEncoderDecoderTest {
    private static final String PRINCIPAL = "sub";
    private static final String AUTHORITIES = "authorities";

    private KeyPair keyPair(String algorithm, int size) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        if (algorithm.equals("RSA")) generator.initialize(size);
        if (algorithm.equals("EC")) generator.initialize(new ECGenParameterSpec(switch (size) {
            case 256 -> "secp256r1";
            case 384 -> "secp384r1";
            case 521 -> "secp521r1";
            default -> throw new IllegalArgumentException("Unsupported EC size");
        }));
        if (algorithm.equals("EdDSA")) generator.initialize(new NamedParameterSpec(size == 448 ? "Ed448" : "Ed25519"));
        return generator.generateKeyPair();
    }

    private SecretKey hmacKey(int bits) {
        byte[] bytes = new byte[bits / 8];
        new SecureRandom().nextBytes(bytes);
        String algorithm = switch (bits) {
            case 256 -> "HmacSHA256";
            case 384 -> "HmacSHA384";
            case 512 -> "HmacSHA512";
            default -> throw new IllegalArgumentException("Unsupported HMAC key size");
        };
        return new SecretKeySpec(bytes, algorithm);
    }

    private void roundTrip(JwtAlgorithm algorithm, Key signingKey, Key verificationKey) {
        JwtConfiguration config = new JwtConfiguration(algorithm, verificationKey, PRINCIPAL, AUTHORITIES);
        JjwtJwtEncoder encoder = new JjwtJwtEncoder(algorithm, signingKey);
        JjwtJwtDecoder decoder = new JjwtJwtDecoder(config);

        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put(PRINCIPAL, "user-1");
        claims.put(AUTHORITIES, java.util.List.of("ROLE_USER"));
        claims.put("exp", java.util.Date.from(Instant.now().plusSeconds(300)));

        String token = encoder.encode(claims);
        JwtClaims decoded = decoder.decode(token);

        assertEquals("user-1", decoded.getString(PRINCIPAL));
        assertEquals(java.util.List.of("ROLE_USER"), decoded.get(AUTHORITIES));
    }

    @Test
    void roundTripsAllHmacAlgorithms() {
        SecretKey key256 = hmacKey(256);
        roundTrip(JwtAlgorithm.HS256, key256, key256);

        SecretKey key384 = hmacKey(384);
        roundTrip(JwtAlgorithm.HS384, key384, key384);

        SecretKey key512 = hmacKey(512);
        roundTrip(JwtAlgorithm.HS512, key512, key512);
    }

    @Test
    void roundTripsHs384AndHs512() {
        SecretKey key384 = hmacKey(384);
        roundTrip(JwtAlgorithm.HS384, key384, key384);
        SecretKey key512 = hmacKey(512);
        roundTrip(JwtAlgorithm.HS512, key512, key512);
    }

    @Test
    void roundTripsAllRsaAlgorithms() throws Exception {
        KeyPair pair = keyPair("RSA", 2048);
        roundTrip(JwtAlgorithm.RS256, pair.getPrivate(), pair.getPublic());
        roundTrip(JwtAlgorithm.RS384, pair.getPrivate(), pair.getPublic());
        roundTrip(JwtAlgorithm.RS512, pair.getPrivate(), pair.getPublic());
    }

    @Test
    void roundTripsAllEcAlgorithms() throws Exception {
        KeyPair p256 = keyPair("EC", 256);
        roundTrip(JwtAlgorithm.ES256, p256.getPrivate(), p256.getPublic());

        KeyPair p384 = keyPair("EC", 384);
        roundTrip(JwtAlgorithm.ES384, p384.getPrivate(), p384.getPublic());

        KeyPair p521 = keyPair("EC", 521);
        roundTrip(JwtAlgorithm.ES512, p521.getPrivate(), p521.getPublic());
    }

    @Test
    void roundTripsEdDsaWithEd25519AndEd448() throws Exception {
        KeyPair ed25519 = keyPair("EdDSA", 255);
        roundTrip(JwtAlgorithm.EDDSA, ed25519.getPrivate(), ed25519.getPublic());

        KeyPair ed448 = keyPair("EdDSA", 448);
        roundTrip(JwtAlgorithm.EDDSA, ed448.getPrivate(), ed448.getPublic());
    }

    @Test
    void rejectsExpiredTokenUsingInjectedClock() {
        SecretKey key = hmacKey(256);
        Instant issuedAt = Instant.parse("2026-01-01T00:00:00Z");
        Clock generationClock = Clock.fixed(issuedAt, ZoneOffset.UTC);
        Clock expiredClock = Clock.fixed(issuedAt.plusSeconds(120), ZoneOffset.UTC);

        JwtConfiguration config = new JwtConfiguration(JwtAlgorithm.HS256, key, PRINCIPAL, AUTHORITIES);
        JwtTokenService service = new JwtTokenService(
                new JjwtJwtEncoder(JwtAlgorithm.HS256, key), config, Duration.ofSeconds(60), generationClock);

        String token = service.generateToken(
                new Authentication() {
                    @Override
                    public Object getPrincipal() { return "user-1"; }
                    @Override
                    public Object getCredentials() { return null; }
                    @Override
                    public java.util.Collection<com.minisec.core.authentication.GrantedAuthority> getAuthorities() {
                        return java.util.List.of();
                    }
                    @Override
                    public boolean isAuthenticated() { return true; }
                });

        JjwtJwtDecoder decoder = new JjwtJwtDecoder(config, expiredClock);
        assertThrows(JwtAuthenticationException.class, () -> decoder.decode(token));
    }

    @Test
    void rejectsTamperedToken() {
        SecretKey key = hmacKey(256);
        JwtConfiguration config = new JwtConfiguration(JwtAlgorithm.HS256, key, PRINCIPAL, AUTHORITIES);
        String token = new JjwtJwtEncoder(JwtAlgorithm.HS256, key)
                .encode(Map.of(PRINCIPAL, "user-1"));

        String[] parts = token.split("\\.");
        assertEquals(3, parts.length);

        char first = parts[1].charAt(0);
        parts[1] = (first == 'A' ? "B" : "A") + parts[1].substring(1);
        String tampered = String.join(".", parts);

        assertThrows(JwtAuthenticationException.class,
                () -> new JjwtJwtDecoder(config).decode(tampered));
    }

    @Test
    void rejectsWrongVerificationKey() {
        SecretKey signingKey = hmacKey(256);
        SecretKey otherKey = hmacKey(256);
        String token = new JjwtJwtEncoder(JwtAlgorithm.HS256, signingKey).encode(Map.of(PRINCIPAL, "user-1"));
        JwtConfiguration config = new JwtConfiguration(JwtAlgorithm.HS256, otherKey, PRINCIPAL, AUTHORITIES);

        assertThrows(JwtAuthenticationException.class, () -> new JjwtJwtDecoder(config).decode(token));
    }

    @Test
    void rejectsAlgorithmMismatch() {
        SecretKey key = hmacKey(512);
        String token = new JjwtJwtEncoder(JwtAlgorithm.HS512, key).encode(Map.of(PRINCIPAL, "user-1"));
        JwtConfiguration config = new JwtConfiguration(JwtAlgorithm.HS256, key, PRINCIPAL, AUTHORITIES);

        assertThrows(JwtAuthenticationException.class, () -> new JjwtJwtDecoder(config).decode(token));
    }

    @Test
    void rejectsBlankMalformedAndOversizedTokens() {
        SecretKey key = hmacKey(256);
        JjwtJwtDecoder decoder = new JjwtJwtDecoder(new JwtConfiguration(JwtAlgorithm.HS256, key, PRINCIPAL, AUTHORITIES));

        assertThrows(JwtAuthenticationException.class, () -> decoder.decode(" "));
        assertThrows(JwtAuthenticationException.class, () -> decoder.decode("not.a.jwt"));
        assertThrows(JwtAuthenticationException.class, () -> decoder.decode("a".repeat(16 * 1024 + 1)));
    }

    @Test
    void jwtClaimsAllowsNullValuedClaims() {
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("middle_name", null);

        JwtClaims jwtClaims = new JwtClaims(claims);

        assertTrue(jwtClaims.claims().containsKey("middle_name"));
        assertNull(jwtClaims.get("middle_name"));

        assertThrows(UnsupportedOperationException.class,
                () -> jwtClaims.claims().put("new_claim", "value"));

        claims.put("another_claim", "value");
        assertFalse(jwtClaims.claims().containsKey("another_claim"));
    }

    @Test
    void rejectsTokenWithoutExpirationClaim() {
        SecretKey key = hmacKey(256);
        JwtConfiguration config = new JwtConfiguration(JwtAlgorithm.HS256, key, PRINCIPAL, AUTHORITIES);

        String token = new JjwtJwtEncoder(JwtAlgorithm.HS256, key)
                .encode(Map.of(PRINCIPAL, "user-1"));

        assertThrows(JwtAuthenticationException.class,
                () -> new JjwtJwtDecoder(config).decode(token));
    }

}