package com.minisec.core.config;

import com.minisec.core.authentication.AuthenticationConverter;
import com.minisec.core.authentication.AuthenticationConverterManager;
import com.minisec.core.authentication.AuthenticationManager;
import com.minisec.core.authentication.AuthenticationProvider;
import com.minisec.core.authentication.ProviderManager;
import com.minisec.core.authorization.AuthorizationManager;
import com.minisec.core.authorization.RequestAuthorizationManager;
import com.minisec.core.authorization.rule.SecurityRuleRegistry;
import com.minisec.core.pipeline.SecurityRequestProcessor;

import java.util.ArrayList;
import java.util.List;

public class SecurityConfiguration {

    private final List<AuthenticationConverter> converters = new ArrayList<>();

    private final List<AuthenticationProvider> providers = new ArrayList<>();

    private final SecurityRuleRegistry ruleRegistry = new SecurityRuleRegistry();

    public void addAuthenticationConverter(AuthenticationConverter converter) {

        converters.add(converter);
    }

    public void addAuthenticationProvider(AuthenticationProvider provider) {

        providers.add(provider);
    }

    public SecurityRuleRegistry getRuleRegistry() {
        return ruleRegistry;
    }

    public SecurityRequestProcessor build() {

        AuthenticationConverterManager converterManager = new AuthenticationConverterManager(converters);

        AuthenticationManager authenticationManager = new ProviderManager(providers);

        AuthorizationManager authorizationManager = new RequestAuthorizationManager(ruleRegistry);

        return new SecurityRequestProcessor(
                converterManager,
                authenticationManager,
                authorizationManager
        );
    }

    public AuthorizationRegistry authorizeHttpRequests() {
        return new AuthorizationRegistry(ruleRegistry);
    }
}