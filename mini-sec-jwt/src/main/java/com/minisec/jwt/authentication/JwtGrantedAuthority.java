package com.minisec.jwt.authentication;

import com.minisec.core.authentication.GrantedAuthority;

public final class JwtGrantedAuthority implements GrantedAuthority {
    private final String authority;

    public JwtGrantedAuthority(String authority) {
        if (authority == null || authority.isBlank())
            throw new IllegalArgumentException("Authority must not be blank");
            this.authority = authority;
    }

    @Override
    public String getAuthority() {
        return authority;
    }
}