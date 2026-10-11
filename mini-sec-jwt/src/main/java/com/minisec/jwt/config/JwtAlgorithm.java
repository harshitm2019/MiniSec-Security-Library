
package com.minisec.jwt.config;

public enum JwtAlgorithm {

    HS256,
    HS384,
    HS512,

    RS256,
    RS384,
    RS512,

    ES256,
    ES384,
    ES512,

    EDDSA;

    public String joseName() {
        return this == EDDSA ? "EdDSA" : name();
    }
}
