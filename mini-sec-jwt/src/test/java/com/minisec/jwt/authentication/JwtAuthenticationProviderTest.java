package com.minisec.jwt.authentication;

import com.minisec.core.authentication.Authentication;
import com.minisec.core.exception.AuthenticationException;
import com.minisec.jwt.JwtAuthoritiesExtractor;
import com.minisec.jwt.JwtClaims;
import com.minisec.jwt.JwtDecoder;
import com.minisec.jwt.JwtPrincipalExtractor;
import com.minisec.jwt.exception.JwtAuthenticationException;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JwtAuthenticationProviderTest {
    @Test
    void authenticatesValidToken() {
        JwtDecoder decoder = token -> new JwtClaims(Map.of("sub", "user-1", "authorities", List.of("ROLE_USER")));
        JwtPrincipalExtractor principalExtractor = claims -> claims.getString("sub");
        JwtAuthoritiesExtractor authoritiesExtractor = claims -> List.of(new JwtGrantedAuthority("ROLE_USER"));
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder, authoritiesExtractor, principalExtractor);

        Authentication result = provider.authenticate(new JwtAuthenticationToken("valid-token"));

        assertTrue(result.isAuthenticated());
        assertEquals("user-1", result.getPrincipal());
        assertEquals(List.of("ROLE_USER"), result.getAuthorities().stream().map(a -> a.getAuthority()).toList());
        assertNull(result.getCredentials());

        JwtAuthenticationToken authenticated = (JwtAuthenticationToken) result;
        assertThrows(IllegalStateException.class, authenticated::getToken);
    }

    @Test
    void rejectsUnsupportedAuthenticationType() {
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(
                token -> new JwtClaims(Map.of()),
                claims -> List.of(),
                claims -> "user"
        );

        Authentication unsupported = new Authentication() {
            public Object getPrincipal() { return "user"; }
            public Object getCredentials() { return null; }
            public java.util.Collection<com.minisec.core.authentication.GrantedAuthority> getAuthorities() { return List.of(); }
            public boolean isAuthenticated() { return false; }
        };

        assertThrows(AuthenticationException.class, () -> provider.authenticate(unsupported));
    }

    @Test
    void propagatesInvalidTokenFailure() {
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(
                token -> { throw new JwtAuthenticationException("Invalid token"); },
                claims -> List.of(),
                claims -> "user"
        );

        assertThrows(JwtAuthenticationException.class, () -> provider.authenticate(new JwtAuthenticationToken("invalid-token")));
    }

    @Test
    void rejectsBlankPrincipal() {
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(
                token -> new JwtClaims(Map.of()),
                claims -> List.of(),
                claims -> " "
        );

        assertThrows(AuthenticationException.class, () -> provider.authenticate(new JwtAuthenticationToken("valid-token")));
    }
}