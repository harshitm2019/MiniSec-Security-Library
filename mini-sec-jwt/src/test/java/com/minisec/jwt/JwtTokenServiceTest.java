package com.minisec.jwt;

import com.minisec.core.authentication.Authentication;
import com.minisec.core.authentication.GrantedAuthority;
import com.minisec.jwt.authentication.JwtGrantedAuthority;
import com.minisec.jwt.config.JwtAlgorithm;
import com.minisec.jwt.config.JwtConfiguration;
import com.minisec.jwt.jjwt.JjwtJwtDecoder;
import com.minisec.jwt.jjwt.JjwtJwtEncoder;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenServiceTest {
    private SecretKey key() {
        return new SecretKeySpec(new byte[32], "HmacSHA256");
    }

    private Authentication authentication(boolean authenticated, Object principal, List<GrantedAuthority> authorities) {
        return new Authentication() {
            @Override
            public Object getPrincipal() { return principal; }

            @Override
            public Object getCredentials() { return null; }

            @Override
            public List<GrantedAuthority> getAuthorities() { return authorities; }

            @Override
            public boolean isAuthenticated() { return authenticated; }
        };
    }

    @Test
    void generatesTokenWithConfiguredClaimsAndLifetime() {
        SecretKey key = key();
        JwtConfiguration config = new JwtConfiguration(JwtAlgorithm.HS256, key, "username", "roles");
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);

        JwtTokenService service = new JwtTokenService(
                new JjwtJwtEncoder(JwtAlgorithm.HS256, key), config, Duration.ofMinutes(15), clock);

        String token = service.generateToken(
                authentication(true, "user-1", List.of(new JwtGrantedAuthority("ROLE_USER"))));

        JwtClaims claims = new JjwtJwtDecoder(config, clock).decode(token);

        assertEquals("user-1", claims.getString("username"));
        assertEquals(List.of("ROLE_USER"), claims.get("roles"));
        assertEquals(now.getEpochSecond(), ((Number) claims.get("iat")).longValue());
        assertEquals(now.plusSeconds(900).getEpochSecond(), ((Number) claims.get("exp")).longValue());
    }


    @Test
    void rejectsUnauthenticatedIdentity() {
        SecretKey key = key();
        JwtConfiguration config = new JwtConfiguration(JwtAlgorithm.HS256, key, "sub", "authorities");
        JwtTokenService service = new JwtTokenService(new JjwtJwtEncoder(JwtAlgorithm.HS256, key), config, Duration.ofMinutes(15));

        assertThrows(IllegalArgumentException.class, () -> service.generateToken(authentication(false, "user-1", List.of())));
    }

    @Test
    void rejectsBlankPrincipal() {
        SecretKey key = key();
        JwtConfiguration config = new JwtConfiguration(JwtAlgorithm.HS256, key, "sub", "authorities");
        JwtTokenService service = new JwtTokenService(new JjwtJwtEncoder(JwtAlgorithm.HS256, key), config, Duration.ofMinutes(15));

        assertThrows(IllegalArgumentException.class, () -> service.generateToken(authentication(true, " ", List.of())));
    }
}