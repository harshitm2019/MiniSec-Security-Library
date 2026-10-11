package com.minisec.jwt.authentication;

import com.minisec.core.authentication.Authentication;
import com.minisec.core.authentication.AuthenticationProvider;
import com.minisec.core.authentication.GrantedAuthority;
import com.minisec.core.exception.AuthenticationException;
import com.minisec.jwt.JwtAuthoritiesExtractor;
import com.minisec.jwt.JwtClaims;
import com.minisec.jwt.JwtDecoder;
import com.minisec.jwt.JwtPrincipalExtractor;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public final class JwtAuthenticationProvider implements AuthenticationProvider {
    private final JwtDecoder jwtDecoder;
    private final JwtAuthoritiesExtractor authoritiesExtractor;
    private final JwtPrincipalExtractor principalExtractor;

    public JwtAuthenticationProvider(JwtDecoder jwtDecoder,
                                     JwtAuthoritiesExtractor authoritiesExtractor,
                                     JwtPrincipalExtractor principalExtractor) {
        if (jwtDecoder == null || authoritiesExtractor == null || principalExtractor == null) {
            throw new IllegalArgumentException("JWT provider dependencies must not be null");
        }
        this.jwtDecoder = jwtDecoder;
        this.authoritiesExtractor = authoritiesExtractor;
        this.principalExtractor = principalExtractor;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        if (!(authentication instanceof JwtAuthenticationToken token)) {
            throw new AuthenticationException("Unsupported authentication type");
        }

        JwtClaims claims = jwtDecoder.decode(token.getToken());
        Object principal = principalExtractor.extract(claims);

        if (!(principal instanceof String name) || name.isBlank()) {
            throw new AuthenticationException("JWT principal must be a nonblank string");
        }

        Collection<? extends GrantedAuthority> extracted = authoritiesExtractor.extract(claims);
        if (extracted == null)
            throw new AuthenticationException("JWT authorities must not be null");

        List<GrantedAuthority> authorities = new ArrayList<>(extracted.size());
        for (GrantedAuthority authority : extracted) {
            if (authority == null || authority.getAuthority() == null || authority.getAuthority().isBlank()) {
                throw new AuthenticationException("JWT authorities must not contain null or blank values");
            }
            authorities.add(authority);
        }
        return JwtAuthenticationToken.authenticated(name, List.copyOf(authorities));

    }

    @Override
    public boolean supports(Class<?> authenticationType) {
        return authenticationType != null &&
                JwtAuthenticationToken.class.isAssignableFrom(authenticationType);
    }
}