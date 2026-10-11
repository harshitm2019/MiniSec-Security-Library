package com.minisec.jwt.authentication;

import com.minisec.core.authentication.AuthenticationConverter;
import com.minisec.core.authentication.AuthenticationToken;
import com.minisec.core.request.SecurityRequest;

public class JwtAuthenticationConverter implements AuthenticationConverter {

    @Override
    public AuthenticationToken convert(SecurityRequest request) {

        String authorization = request.getHeader("Authorization");

        if (authorization == null) {
            return null;
        }

        if (!authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }

        String token = authorization.substring(7).trim();

        if (token.isEmpty()) {
            return null;
        }

        return new JwtAuthenticationToken(token);
    }
}