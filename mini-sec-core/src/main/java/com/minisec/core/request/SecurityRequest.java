package com.minisec.core.request;

import java.util.Collections;
import java.util.Map;

public record SecurityRequest(
        String path,
        String method,
        Map<String, String> headers
) {

    public SecurityRequest {
        headers = headers == null
                ? Collections.emptyMap()
                : Map.copyOf(headers);
    }

    public String getHeader(String name) {
        if (name == null) {
            return null;
        }

        return headers.entrySet().stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase(name))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(null);
    }

}