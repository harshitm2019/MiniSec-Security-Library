package com.minisec.jwt;

import com.minisec.core.authentication.GrantedAuthority;

import java.util.Collection;

public interface JwtAuthoritiesExtractor {

    Collection<? extends GrantedAuthority> extract(JwtClaims claims);

}
