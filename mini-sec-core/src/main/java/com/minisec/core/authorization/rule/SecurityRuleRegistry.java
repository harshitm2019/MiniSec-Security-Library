package com.minisec.core.authorization.rule;

import java.util.ArrayList;
import java.util.List;

public class SecurityRuleRegistry {

    private final List<RequestRule> rules = new ArrayList<>();

    public void addRule(RequestRule rule) {
        rules.add(rule);
    }

    public List<RequestRule> getRules() {
        return List.copyOf(rules);
    }
}