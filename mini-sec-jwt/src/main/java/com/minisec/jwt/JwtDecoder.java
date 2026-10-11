package com.minisec.jwt;

public interface JwtDecoder {

    JwtClaims decode(String token);

}
