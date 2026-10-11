package com.minisec.jwt.config;

import com.minisec.jwt.JwtAuthoritiesExtractor;
import com.minisec.jwt.JwtDecoder;
import com.minisec.jwt.JwtPrincipalExtractor;
import com.minisec.jwt.authentication.DefaultJwtAuthoritiesExtractor;
import com.minisec.jwt.authentication.DefaultJwtPrincipalExtractor;
import com.minisec.jwt.authentication.JwtAuthenticationProvider;
import com.minisec.jwt.jjwt.JjwtJwtDecoder;

public final class JwtAuthenticationProviderFactory {
    public JwtAuthenticationProvider create(JwtConfiguration configuration) {
        if (configuration == null)
            throw new IllegalArgumentException("JWT configuration must not be null");

        JwtDecoder decoder = new JjwtJwtDecoder(configuration);

        JwtPrincipalExtractor principalExtractor =
                new DefaultJwtPrincipalExtractor(configuration.principalClaim());

        JwtAuthoritiesExtractor authoritiesExtractor =
                new DefaultJwtAuthoritiesExtractor(configuration.authoritiesClaim());

        return new JwtAuthenticationProvider(decoder, authoritiesExtractor, principalExtractor);
    }
}