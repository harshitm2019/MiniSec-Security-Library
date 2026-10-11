package com.minisec.jwt.jjwt;

import com.minisec.jwt.JwtClaims;
import com.minisec.jwt.JwtDecoder;
import com.minisec.jwt.config.JwtConfiguration;
import com.minisec.jwt.exception.JwtAuthenticationException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.security.SignatureException;

import java.security.Key;
import java.time.Clock;
import java.util.Date;
import java.util.HashMap;

public final class JjwtJwtDecoder implements JwtDecoder {
    private static final int MAX_TOKEN_LENGTH = 16 * 1024;

    private final JwtConfiguration configuration;
    private final Clock clock;

    public JjwtJwtDecoder(JwtConfiguration configuration) {
        this(configuration, Clock.systemUTC());
    }

    public JjwtJwtDecoder(JwtConfiguration configuration, Clock clock) {
        if (configuration == null)
            throw new IllegalArgumentException("JWT configuration must not be null");
        if (clock == null)
            throw new IllegalArgumentException("Clock must not be null");
        this.configuration = configuration;
        this.clock = clock;
    }

    @Override
    public JwtClaims decode(String token) {
        if (token == null || token.isBlank())
            throw new JwtAuthenticationException("JWT must not be blank");
        if (token.length() > MAX_TOKEN_LENGTH)
            throw new JwtAuthenticationException("JWT exceeds the maximum allowed length");

        try {
            Key verificationKey = configuration.verificationKey();
            String expectedAlgorithm = configuration.algorithm().joseName();

            Jws<Claims> jws = Jwts.parser()
                    .clock(() -> Date.from(clock.instant()))
                    .keyLocator(header -> {
                        if (!expectedAlgorithm.equals(header.getAlgorithm())) {
                            throw new JwtAuthenticationException("Unexpected JWT algorithm");
                        }
                        return verificationKey;
                    })
                    .build()
                    .parseSignedClaims(token);

            Claims claims = jws.getPayload();

            if (claims.getExpiration() == null)
                throw new JwtAuthenticationException("JWT expiration claim is required");

            return new JwtClaims(new HashMap<>(claims));

        } catch (ExpiredJwtException ex) {
            throw new JwtAuthenticationException("JWT has expired", ex);
        } catch (MalformedJwtException ex) {
            throw new JwtAuthenticationException("JWT is malformed", ex);
        } catch (SignatureException ex) {
            throw new JwtAuthenticationException("JWT signature validation failed", ex);
        } catch (JwtException ex) {
            throw new JwtAuthenticationException("JWT validation failed", ex);
        }
    }
}