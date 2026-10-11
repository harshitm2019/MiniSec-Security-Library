package com.minisec.core.authentication;

import com.minisec.core.request.SecurityRequest;

public interface AuthenticationConverter {

    /**
     * Attempts to extract authentication credentials
     * from the incoming security request.
     *
     * @param request incoming security request
     * @return authentication token if this converter
     *         recognizes the request; otherwise null
     */

    AuthenticationToken convert(SecurityRequest request);
}