package com.minisec.jwt.config;

import java.security.Key;
import java.util.Objects;
import java.util.Set;

public record JwtConfiguration(
        JwtAlgorithm algorithm,
        Key verificationKey,
        String principalClaim,
        String authoritiesClaim
) {

    private static final Set<String> RESERVED_CLAIMS = Set.of("iat", "exp", "nbf");

    public JwtConfiguration {

        Objects.requireNonNull(algorithm, "JWT algorithm must not be null");
        Objects.requireNonNull(verificationKey, "JWT verification key must not be null");

        if (principalClaim == null || principalClaim.isBlank()) {
            throw new IllegalArgumentException("JWT principal claim must not be blank");
        }
        if (authoritiesClaim == null || authoritiesClaim.isBlank()) {
            throw new IllegalArgumentException("JWT authorities claim must not be blank");
        }
        if (principalClaim.equals(authoritiesClaim)) {
            throw new IllegalArgumentException("Principal and authorities claims must be different");
        }
        if (RESERVED_CLAIMS.contains(principalClaim) || RESERVED_CLAIMS.contains(authoritiesClaim)) {
            throw new IllegalArgumentException("Principal and authorities claims must not use iat, exp, or nbf");
        }

        JwtKeyValidator.validateVerificationKey(algorithm, verificationKey);
    }
}