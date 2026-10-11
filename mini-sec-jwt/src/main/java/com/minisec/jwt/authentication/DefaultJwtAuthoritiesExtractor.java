package com.minisec.jwt.authentication;

import com.minisec.core.authentication.GrantedAuthority;
import com.minisec.jwt.JwtAuthoritiesExtractor;
import com.minisec.jwt.JwtClaims;
import com.minisec.jwt.exception.JwtAuthenticationException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public final class DefaultJwtAuthoritiesExtractor
        implements JwtAuthoritiesExtractor {

    private final String claimName;

    public DefaultJwtAuthoritiesExtractor(String claimName) {
        if (claimName == null || claimName.isBlank()) {
            throw new IllegalArgumentException("Authorities claim name must not be blank");
        }

        this.claimName = claimName;
    }

    @Override
    public Collection<? extends GrantedAuthority> extract(
            JwtClaims claims) {

        if (claims == null) {
            throw new JwtAuthenticationException("JWT claims must not be null");
        }

        Object value = claims.get(claimName);

        // Missing authorities means the token grants no authorities.
        if (value == null) {
            return List.of();
        }

        List<String> names = new ArrayList<>();

        if (value instanceof String authority) {
            names.add(authority);

        } else if (value instanceof Collection<?> authorities) {
            for (Object authority : authorities) {
                if (!(authority instanceof String name)) {
                    throw new JwtAuthenticationException("JWT authority values must be strings");
                }

                names.add(name);
            }

        } else {
            throw new JwtAuthenticationException("JWT authorities claim has an invalid format");
        }

        List<GrantedAuthority> result = new ArrayList<>();

        for (String name : names) {
            if (name == null || name.isBlank()) {
                throw new JwtAuthenticationException("JWT authority must not be blank");
            }

            result.add(new JwtGrantedAuthority(name));
        }

        return List.copyOf(result);
    }
}