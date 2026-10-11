package com.minisec.jwt.authentication;

import com.minisec.jwt.JwtClaims;
import com.minisec.jwt.JwtPrincipalExtractor;
import com.minisec.jwt.exception.JwtAuthenticationException;

public final class DefaultJwtPrincipalExtractor
        implements JwtPrincipalExtractor {

    private final String claimName;

    public DefaultJwtPrincipalExtractor(String claimName) {
        if (claimName == null || claimName.isBlank()) {
            throw new IllegalArgumentException("Principal claim name must not be blank");
        }

        this.claimName = claimName;
    }

    @Override
    public Object extract(JwtClaims claims) {
        if (claims == null) {
            throw new JwtAuthenticationException("JWT claims must not be null");
        }

        Object principal = claims.get(claimName);

        if (principal == null || principal.toString().isBlank()) {
            throw new JwtAuthenticationException("JWT principal claim is missing or blank");
        }

        if (!(principal instanceof String)) {
            throw new JwtAuthenticationException("JWT principal claim must be a string");
        }

        return principal;
    }
}