package com.minisec.core.authorization;

public record RequestAuthorizationResource(
        String path,
        String method
) {
}