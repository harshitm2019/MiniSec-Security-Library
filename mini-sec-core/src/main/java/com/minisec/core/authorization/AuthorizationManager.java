package com.minisec.core.authorization;


import com.minisec.core.authentication.Authentication;

public interface AuthorizationManager {

    AuthorizationDecision check(
            Authentication authentication,
            Object resource
    );

}
