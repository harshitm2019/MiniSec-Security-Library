package com.minisec.core.authorization;

import com.minisec.core.authentication.Authentication;
import com.minisec.core.authorization.rule.RequestRule;
import com.minisec.core.authorization.rule.SecurityRuleRegistry;

public class RequestAuthorizationManager implements AuthorizationManager {

    private final SecurityRuleRegistry ruleRegistry;

    public RequestAuthorizationManager(SecurityRuleRegistry ruleRegistry) {
        this.ruleRegistry = ruleRegistry;
    }

    @Override
    public AuthorizationDecision check(Authentication authentication, Object resource) {

        if (!(resource instanceof RequestAuthorizationResource(
                String path, String method
        ))) {
            throw new IllegalArgumentException("Unsupported authorization resource");
        }

        for (RequestRule rule : ruleRegistry.getRules()) {

            if (!rule.getMatcher().matches(path, method)) {
                continue;
            }

            return evaluateRule(rule, authentication);
        }

        // No matching rule → deny by default
        return new AuthorizationDecision(false);
    }

    private AuthorizationDecision evaluateRule(
            RequestRule rule,
            Authentication authentication) {

        return switch (rule.getRuleType()) {

            case PERMIT_ALL -> new AuthorizationDecision(true);

            case AUTHENTICATED ->
                    new AuthorizationDecision(authentication != null && authentication.isAuthenticated());

            case HAS_AUTHORITY ->
                    new AuthorizationDecision(
                            hasAuthority(authentication, rule.getRequiredAuthority())
                    );
        };
    }

    private boolean hasAuthority(Authentication authentication, String requiredAuthority) {

        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        return authentication.getAuthorities()
                .stream()
                .anyMatch(
                        authority -> authority.getAuthority()
                                .equals(requiredAuthority)
                );
    }
}