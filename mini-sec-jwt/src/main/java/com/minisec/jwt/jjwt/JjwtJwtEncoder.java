package com.minisec.jwt.jjwt;

import com.minisec.jwt.JwtEncoder;
import com.minisec.jwt.config.JwtAlgorithm;
import com.minisec.jwt.config.JwtKeyValidator;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Map;

public final class JjwtJwtEncoder implements JwtEncoder {
    private final JwtAlgorithm algorithm;
    private final Key signingKey;

    public JjwtJwtEncoder(JwtAlgorithm algorithm, Key signingKey) {
        JwtKeyValidator.validateSigningKey(algorithm, signingKey);
        this.algorithm = algorithm;
        this.signingKey = signingKey;
    }

    @Override
    public String encode(Map<String, Object> claims) {
        if (claims == null) throw new IllegalArgumentException("JWT claims must not be null");

        var builder = Jwts.builder().claims(claims);

        return switch (algorithm) {
            case HS256 ->
                    builder.signWith((SecretKey) signingKey, Jwts.SIG.HS256).compact();
            case HS384 ->
                    builder.signWith((SecretKey) signingKey, Jwts.SIG.HS384).compact();
            case HS512 ->
                    builder.signWith((SecretKey) signingKey, Jwts.SIG.HS512).compact();
            case RS256 ->
                    builder.signWith((RSAPrivateKey) signingKey, Jwts.SIG.RS256).compact();
            case RS384 ->
                    builder.signWith((RSAPrivateKey) signingKey, Jwts.SIG.RS384).compact();
            case RS512 ->
                    builder.signWith((RSAPrivateKey) signingKey, Jwts.SIG.RS512).compact();
            case ES256 ->
                    builder.signWith((ECPrivateKey) signingKey, Jwts.SIG.ES256).compact();
            case ES384 ->
                    builder.signWith((ECPrivateKey) signingKey, Jwts.SIG.ES384).compact();
            case ES512 ->
                    builder.signWith((ECPrivateKey) signingKey, Jwts.SIG.ES512).compact();
            case EDDSA ->
                    builder.signWith((EdECPrivateKey) signingKey, Jwts.SIG.EdDSA).compact();
        };
    }
}