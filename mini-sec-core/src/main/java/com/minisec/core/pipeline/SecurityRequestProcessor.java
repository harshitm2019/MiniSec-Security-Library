package com.minisec.core.pipeline;

import com.minisec.core.authentication.*;
import com.minisec.core.authorization.AuthorizationDecision;
import com.minisec.core.authorization.AuthorizationManager;
import com.minisec.core.authorization.RequestAuthorizationResource;
import com.minisec.core.context.SecurityContextHolder;
import com.minisec.core.request.SecurityRequest;

public class SecurityRequestProcessor {
    private final AuthenticationManager authenticationManager;
    private final AuthorizationManager authorizationManager;
    private final AuthenticationConverterManager authenticationConverterManager;

    public SecurityRequestProcessor(AuthenticationConverterManager converterManager,
                                    AuthenticationManager authenticationManager,
                                    AuthorizationManager authorizationManager) {
        this.authenticationConverterManager = converterManager;
        this.authenticationManager = authenticationManager;
        this.authorizationManager = authorizationManager;
    }

    /**
     * Processes a request and retains its context for the caller's request lifecycle.
     * The adapter must clear SecurityContextHolder after completing the request.
     */
    public SecurityResult process(SecurityRequest request) {
        Authentication authentication = authenticate(request);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        AuthorizationDecision decision = authorize(request, authentication);

        if (decision.isGranted())
            return SecurityResult.allowed();
        return authentication == null ? SecurityResult.unauthenticated() : SecurityResult.forbidden();
    }

    private Authentication authenticate(SecurityRequest request) {
        AuthenticationToken token = authenticationConverterManager.convert(request);
        return token == null ? null : authenticationManager.authenticate(token);
    }

    private AuthorizationDecision authorize(SecurityRequest request, Authentication authentication) {
        RequestAuthorizationResource resource =
                new RequestAuthorizationResource(request.path(), request.method());
        return authorizationManager.check(authentication, resource);
    }
}