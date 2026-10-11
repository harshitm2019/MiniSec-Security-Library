package com.minisec.core.authentication;

import java.util.Collection;

public interface Authentication {

    Object getPrincipal();

    Object getCredentials();

    Collection<? extends GrantedAuthority> getAuthorities();

    boolean isAuthenticated();

}
