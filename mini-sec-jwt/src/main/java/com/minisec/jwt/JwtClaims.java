
package com.minisec.jwt;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public record JwtClaims(Map<String, Object> claims) {

    public JwtClaims {
        if (claims == null)
            throw new IllegalArgumentException("JWT claims must not be null");

        claims = Collections.unmodifiableMap(new HashMap<>(claims));
    }

    public Object get(String name) {
        return claims.get(name);
    }

    public String getString(String name) {
        Object value = claims.get(name);
        return value != null ? value.toString() : null;
    }
}
