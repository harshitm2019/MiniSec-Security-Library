package com.minisec.jwt;

public interface JwtPrincipalExtractor {

    Object extract(JwtClaims claims);

}
