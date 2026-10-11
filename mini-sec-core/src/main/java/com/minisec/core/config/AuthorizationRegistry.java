package com.minisec.core.config;

import com.minisec.core.authorization.matcher.AntPathRequestMatcher;
import com.minisec.core.authorization.rule.RequestRule;
import com.minisec.core.authorization.rule.RuleType;
import com.minisec.core.authorization.rule.SecurityRuleRegistry;

public class AuthorizationRegistry {

    private final SecurityRuleRegistry ruleRegistry;

    public AuthorizationRegistry(SecurityRuleRegistry ruleRegistry) {

        this.ruleRegistry = ruleRegistry;

    }

    public AuthorizationRegistry permitAll(String pattern) {

        ruleRegistry.addRule(new RequestRule(new AntPathRequestMatcher(pattern),
                        RuleType.PERMIT_ALL,
                        null
                )
        );

        return this;
    }

    public AuthorizationRegistry permitAll(String pattern, String method) {

        ruleRegistry.addRule(new RequestRule(new AntPathRequestMatcher(pattern, method),
                        RuleType.PERMIT_ALL,
                        null
                )
        );

        return this;
    }

    public AuthorizationRegistry authenticated(String pattern) {

        ruleRegistry.addRule(new RequestRule(new AntPathRequestMatcher(pattern),
                        RuleType.AUTHENTICATED,
                        null
                )
        );

        return this;
    }

    public AuthorizationRegistry authenticated(String pattern, String method) {

        ruleRegistry.addRule(new RequestRule(new AntPathRequestMatcher(pattern, method),
                        RuleType.AUTHENTICATED,
                        null
                )
        );

        return this;
    }

    public AuthorizationRegistry hasAuthority(String pattern, String authority) {

        ruleRegistry.addRule(new RequestRule(new AntPathRequestMatcher(pattern),
                        RuleType.HAS_AUTHORITY,
                        authority
                )
        );

        return this;
    }

    public AuthorizationRegistry hasAuthority(String pattern, String method, String authority) {

        ruleRegistry.addRule(new RequestRule(new AntPathRequestMatcher(pattern, method),
                        RuleType.HAS_AUTHORITY,
                        authority
                )
        );

        return this;
    }
}