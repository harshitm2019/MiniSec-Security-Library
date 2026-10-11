package com.minisec.core.authorization.rule;

import com.minisec.core.authorization.matcher.RequestMatcher;

public final class RequestRule {


    private final RequestMatcher matcher;
    private final RuleType ruleType;
    private final String requiredAuthority;

    public RequestRule(
            RequestMatcher matcher,
            RuleType ruleType,
            String requiredAuthority) {

        this.matcher = matcher;
        this.ruleType = ruleType;
        this.requiredAuthority = requiredAuthority;
    }

    public RequestMatcher getMatcher() {
        return matcher;
    }

    public RuleType getRuleType() {
        return ruleType;
    }

    public String getRequiredAuthority() {
        return requiredAuthority;
    }
}