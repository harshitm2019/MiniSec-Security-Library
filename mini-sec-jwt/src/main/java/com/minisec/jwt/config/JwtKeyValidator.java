package com.minisec.jwt.config;

import javax.crypto.SecretKey;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.interfaces.*;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

public final class JwtKeyValidator {

    private JwtKeyValidator() {}

    public static void validateSigningKey(JwtAlgorithm algorithm, Key key) {
        validate(algorithm, key, true);
    }

    public static void validateVerificationKey(JwtAlgorithm algorithm, Key key) {
        validate(algorithm, key, false);
    }

    private static void validate(JwtAlgorithm algorithm, Key key, boolean signing) {
        if (algorithm == null) throw new IllegalArgumentException("JWT algorithm must not be null");
        if (key == null) throw new IllegalArgumentException("JWT key must not be null");

        boolean compatible = switch (algorithm) {
            case HS256, HS384, HS512 -> key instanceof SecretKey;
            case RS256, RS384, RS512 -> signing ? key instanceof RSAPrivateKey : key instanceof RSAPublicKey;
            case ES256, ES384, ES512 -> signing ? key instanceof ECPrivateKey : key instanceof ECPublicKey;
            case EDDSA -> signing ? key instanceof EdECPrivateKey : key instanceof EdECPublicKey;
        };

        if (!compatible) {
            throw new IllegalArgumentException("Key type is incompatible with JWT "
                    + (signing ? "signing" : "verification") + " algorithm " + algorithm);
        }

        switch (algorithm) {
            case HS256, HS384, HS512 -> validateHmacKey(algorithm, (SecretKey) key);
            case RS256, RS384, RS512 -> validateRsaKey((RSAKey) key);
            case ES256, ES384, ES512 -> validateEcKey(algorithm, key);
            case EDDSA -> validateEdDsaKey(key);
        }
    }

    private static void validateHmacKey(JwtAlgorithm algorithm, SecretKey key) {
        String keyAlgorithm = key.getAlgorithm();
        if (keyAlgorithm == null || !keyAlgorithm.regionMatches(true, 0, "Hmac", 0, 4)) {
            throw new IllegalArgumentException("HMAC JWT algorithms require an HMAC secret key");
        }

        byte[] encoded = key.getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw new IllegalArgumentException("Cannot validate HMAC key strength: key material is not extractable");
        }

        int requiredBits = switch (algorithm) {
            case HS256 -> 256;
            case HS384 -> 384;
            case HS512 -> 512;
            default -> throw new IllegalArgumentException("Not an HMAC algorithm: " + algorithm);
        };

        int actualBits = encoded.length * Byte.SIZE;
        if (actualBits < requiredBits) {
            throw new IllegalArgumentException(algorithm + " requires an HMAC key of at least "
                    + requiredBits + " bits; actual length is " + actualBits + " bits");
        }
    }

    private static void validateRsaKey(RSAKey key) {
        if (key.getModulus() == null) throw new IllegalArgumentException("RSA key modulus must not be null");

        int actualBits = key.getModulus().bitLength();
        if (actualBits < 2048) {
            throw new IllegalArgumentException("RSA JWT keys must be at least 2048 bits; actual size is " + actualBits + " bits");
        }
    }

    private static void validateEcKey(JwtAlgorithm algorithm, Key key) {
        ECParameterSpec actual = switch (key) {
            case ECPrivateKey k -> k.getParams();
            case ECPublicKey k -> k.getParams();
            default -> throw new IllegalArgumentException("Invalid EC key for " + algorithm);
        };

        String requiredCurve = switch (algorithm) {
            case ES256 -> "secp256r1";
            case ES384 -> "secp384r1";
            case ES512 -> "secp521r1";
            default -> throw new IllegalArgumentException("Not an ECDSA algorithm: " + algorithm);
        };

        if (!sameCurve(actual, namedCurve(requiredCurve))) {
            throw new IllegalArgumentException(algorithm + " requires the " + requiredCurve + " elliptic curve");
        }
    }

    private static ECParameterSpec namedCurve(String curveName) {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(curveName));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Unable to load required EC curve: " + curveName, ex);
        }
    }

    private static boolean sameCurve(ECParameterSpec actual, ECParameterSpec expected) {
        if (actual == null || expected == null) return false;

        // JWT ECDSA curves must use prime fields.
        if (!(actual.getCurve().getField() instanceof ECFieldFp actualField)
                || !(expected.getCurve().getField() instanceof ECFieldFp expectedField)) {
            return false;
        }

        return actualField.getP().equals(expectedField.getP())
                && actual.getCurve().getA().equals(expected.getCurve().getA())
                && actual.getCurve().getB().equals(expected.getCurve().getB())
                && actual.getGenerator().getAffineX().equals(expected.getGenerator().getAffineX())
                && actual.getGenerator().getAffineY().equals(expected.getGenerator().getAffineY())
                && actual.getOrder().equals(expected.getOrder())
                && actual.getCofactor() == expected.getCofactor();
    }

    private static void validateEdDsaKey(Key key) {
        String curve = switch (key) {
            case EdECPrivateKey k -> k.getParams().getName();
            case EdECPublicKey k -> k.getParams().getName();
            default -> throw new IllegalArgumentException("EdDSA requires an Ed25519 or Ed448 key");
        };

        if (!"Ed25519".equalsIgnoreCase(curve) && !"Ed448".equalsIgnoreCase(curve)) {
            throw new IllegalArgumentException("Unsupported EdDSA curve: " + curve);
        }
    }
}