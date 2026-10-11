package com.minisec.core.authentication;


import com.minisec.core.exception.AuthenticationException;

import java.util.List;

public class ProviderManager implements AuthenticationManager {

    private final List<AuthenticationProvider> providers;

    public ProviderManager(List<AuthenticationProvider> providers) {
        this.providers = List.copyOf(providers);
    }

    @Override
    public Authentication authenticate(Authentication authentication) {

        for (AuthenticationProvider provider : providers) {

            if (!provider.supports(authentication.getClass())) {
                continue;
            }

            Authentication result = provider.authenticate(authentication);

            if (result != null) {
                return result;
            }
        }

        throw new AuthenticationException("No suitable authentication provider found");
    }
}