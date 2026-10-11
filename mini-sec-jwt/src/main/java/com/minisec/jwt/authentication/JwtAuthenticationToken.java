
package com.minisec.jwt.authentication;

import com.minisec.core.authentication.AuthenticationToken;
import com.minisec.core.authentication.GrantedAuthority;

import java.util.Collection;
import java.util.List;

public final class JwtAuthenticationToken implements AuthenticationToken {

    private final String token;
    private final Object principal;
    private final List<? extends GrantedAuthority> authorities;
    private final boolean authenticated;

    public JwtAuthenticationToken(String token) {
        this(token, null, List.of(), false);
    }

    private JwtAuthenticationToken(String token, Object principal,
                                   List<? extends GrantedAuthority> authorities,
                                   boolean authenticated) {
        if (authenticated && token != null)
            throw new IllegalArgumentException("Authenticated tokens must not retain JWT credentials");
        if (!authenticated && (token == null || token.isBlank()))
            throw new IllegalArgumentException("JWT must not be blank");
        if (authorities == null)
            throw new IllegalArgumentException("Authorities must not be null");
        if (authenticated && (!(principal instanceof String name) || name.isBlank()))
            throw new IllegalArgumentException("Authenticated principal must be a nonblank string");

        for (GrantedAuthority authority : authorities) {
            if (authority == null || authority.getAuthority() == null || authority.getAuthority().isBlank())
                throw new IllegalArgumentException("Authorities must not contain null or blank values");
        }

        this.token = token;
        this.principal = principal;
        this.authorities = List.copyOf(authorities);
        this.authenticated = authenticated;
    }

    public static JwtAuthenticationToken authenticated(
            String principal, List<? extends GrantedAuthority> authorities) {
        return new JwtAuthenticationToken(null, principal, authorities, true);
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public Object getCredentials() {
        return authenticated ? null : token;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    String getToken() {
        if (authenticated)
            throw new IllegalStateException("JWT is unavailable after authentication");
        return token;
    }
}
