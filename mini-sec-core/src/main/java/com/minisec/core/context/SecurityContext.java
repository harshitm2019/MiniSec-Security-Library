package com.minisec.core.context;

import com.minisec.core.authentication.Authentication;

public class SecurityContext {

    private Authentication authentication;

    public Authentication getAuthentication() {
        return authentication;
    }

    public void setAuthentication(Authentication authentication) {
        this.authentication = authentication;
    }

}
