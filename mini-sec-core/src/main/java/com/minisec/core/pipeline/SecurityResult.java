package com.minisec.core.pipeline;

public final class SecurityResult {

    public enum Status {
        ALLOWED,
        UNAUTHENTICATED,
        FORBIDDEN,
    }

    private final Status status;

    private SecurityResult(Status status) {
        this.status = status;
    }

    public static SecurityResult allowed() {
        return new SecurityResult(Status.ALLOWED);
    }

    public static SecurityResult forbidden() {
        return new SecurityResult(Status.FORBIDDEN);
    }

    public static SecurityResult unauthenticated() {
        return new SecurityResult(Status.UNAUTHENTICATED);
    }

    public Status getStatus() {
        return status;
    }

    public boolean isAllowed() {
        return status == Status.ALLOWED;
    }

    public boolean isForbidden() {
        return status == Status.FORBIDDEN;
    }

    public boolean isUnauthenticated() {
        return status == Status.UNAUTHENTICATED;
    }
}