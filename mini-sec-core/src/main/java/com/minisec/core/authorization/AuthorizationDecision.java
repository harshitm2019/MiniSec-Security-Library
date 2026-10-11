package com.minisec.core.authorization;

public final class AuthorizationDecision {

    private final boolean granted;

    public AuthorizationDecision(boolean granted) {
        this.granted = granted;
    }

    public boolean isGranted() {
        return granted;
    }

}
