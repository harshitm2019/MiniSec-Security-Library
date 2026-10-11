package com.minisec.jwt;

import com.minisec.core.authentication.Authentication;
import com.minisec.core.authentication.GrantedAuthority;
import com.minisec.jwt.config.JwtConfiguration;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.DateTimeException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class JwtTokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtConfiguration configuration;
    private final Duration tokenLifetime;
    private final Clock clock;

    public JwtTokenService(JwtEncoder jwtEncoder,
                           JwtConfiguration configuration,
                           Duration tokenLifetime) {
        this(jwtEncoder, configuration, tokenLifetime, Clock.systemUTC());
    }

    public JwtTokenService(JwtEncoder jwtEncoder,
                           JwtConfiguration configuration,
                           Duration tokenLifetime,
                           Clock clock) {
        if (jwtEncoder == null || configuration == null || tokenLifetime == null
                || tokenLifetime.isZero() || tokenLifetime.isNegative() || clock == null) {
            throw new IllegalArgumentException("Invalid JWT token service configuration");
        }

        this.jwtEncoder = jwtEncoder;
        this.configuration = configuration;
        this.tokenLifetime = tokenLifetime;
        this.clock = clock;
    }

    public String generateToken(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalArgumentException("An authenticated identity is required");
        }

        if (!(authentication.getPrincipal() instanceof String principal) || principal.isBlank()) {
            throw new IllegalArgumentException("Principal must be a nonblank string");
        }

        if (authentication.getAuthorities() == null)
            throw new IllegalArgumentException("Authorities must not be null");

        List<String> authorities =
                authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
        if (authorities.stream().anyMatch(a -> a == null || a.isBlank())) {
            throw new IllegalArgumentException("Authorities must not contain null or blank values");
        }

        Instant issuedAt = clock.instant();
        Instant expiresAt;

        try {
            expiresAt = issuedAt.plus(tokenLifetime);
        } catch (ArithmeticException | DateTimeException ex) {
            throw new IllegalArgumentException("JWT token lifetime is out of range", ex);
        }

        Map<String, Object> claims = new HashMap<>();
        claims.put(configuration.principalClaim(), principal);
        claims.put(configuration.authoritiesClaim(), authorities);
        claims.put("iat", Date.from(issuedAt));
        claims.put("exp", Date.from(expiresAt));
        return jwtEncoder.encode(Map.copyOf(claims));
    }
}