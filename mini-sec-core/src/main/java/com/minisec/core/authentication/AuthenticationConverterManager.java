package com.minisec.core.authentication;

import com.minisec.core.request.SecurityRequest;

import java.util.List;

public class AuthenticationConverterManager implements AuthenticationConverter {

    private final List<AuthenticationConverter> converters;

    public AuthenticationConverterManager(List<AuthenticationConverter> converters) {

        this.converters = List.copyOf(converters);
    }

    @Override
    public AuthenticationToken convert(SecurityRequest request) {

        for (AuthenticationConverter converter : converters) {

            AuthenticationToken token = converter.convert(request);

            if (token != null) {
                return token;
            }
        }

        return null;
    }
}