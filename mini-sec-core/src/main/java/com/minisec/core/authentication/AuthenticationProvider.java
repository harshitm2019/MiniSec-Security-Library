package com.minisec.core.authentication;

public interface AuthenticationProvider {

    Authentication authenticate(Authentication authentication);

    boolean supports(Class<?> authenticationType);

}
