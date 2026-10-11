# MiniSec — Lightweight Java Security Framework

MiniSec is a modular Java authentication and authorization framework with JWT support. This repository contains the library source.

The Spring Boot snippets below are integration examples for an application that consumes MiniSec.


## Contents

- [Overview](#overview)
- [Modules](#modules)
- [Current features](#current-features)
- [Build and use locally](#build-and-use-locally)
- [Integration model](#integration-model)
- [Shared servlet filter](#shared-servlet-filter)
- [Choose one of the ten algorithm configurations](#choose-one-of-the-ten-algorithm-configurations)
- [Algorithm examples](#algorithm-examples)
- [Key formats](#key-formats)
- [Expected authorization behavior](#expected-authorization-behavior)
- [Security notes and current limitations](#security-notes-and-current-limitations)
- [Future improvements](#future-improvements)
- [Contributing and license](#contributing-and-license)

## Overview

MiniSec separates security abstractions from JWT-specific functionality. It is designed so that the core security pipeline is not tied to Spring Security. A web application can adapt its incoming requests to MiniSec's request model using a framework-specific filter or adapter.

## Modules

| Module | Purpose |
|---|---|
| `mini-sec-core` | Authentication abstractions, authentication converter/provider managers, authorization rules, request processing, and security context types |
| `mini-sec-jwt` | JWT encoding/decoding, claim extraction, algorithm configuration, key validation, and JWT authentication provider |

## Current features

- Modular Maven build with `mini-sec-core` and `mini-sec-jwt`.
- Authentication converter and provider abstractions.
- Request authorization rules: public, authenticated, and authority-based access.
- JWT bearer-token conversion.
- JWT encoding and decoding using a configured algorithm and key.
- Supported algorithm options: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, and EDDSA (Ed25519 or Ed448 keys).
- Validation of HMAC key lengths, RSA key sizes, ECDSA curves, and key types.
- Rejection of invalid signatures, algorithm mismatch, expired tokens, and tokens missing the required expiration claim.
- Configurable principal and authorities claim names.
- Defensive claims handling and authentication-token behavior covered by the current tests.

Features above describe the current source, not a guarantee that every production deployment requirement is implemented. Review the limitations below before using MiniSec in a service.

## Build and use locally

Requirements: JDK 21 and Maven.

To install the current snapshot artifacts into your local Maven repository for a separate application to consume, run:
mvn clean install

The local coordinates currently use `com.minisec` and version `1.0-SNAPSHOT`. They are local development coordinates, not a published Maven Central release.

A consuming application's `pom.xml` can reference the locally installed modules like this:


<dependency>
    <groupId>com.minisec</groupId>
    <artifactId>mini-sec-core</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
<dependency>
    <groupId>com.minisec</groupId>
    <artifactId>mini-sec-jwt</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>

The consuming application must also have its own web framework dependencies (for example, Spring Boot Web) and runtime dependencies required by the integration.

## Integration model

For a servlet-based Spring Boot application, the integration normally consists of:

1. A servlet `Filter` that adapts HTTP method, request path, and headers into a `SecurityRequest`.
2. A `SecurityConfiguration` that registers `JwtAuthenticationConverter`, a provider created by `JwtAuthenticationProviderFactory`, and endpoint authorization rules.
3. A `JwtConfiguration` with the selected algorithm, verification key, principal claim, and authorities claim.
4. A `JjwtJwtEncoder` configured with the matching algorithm and signing key.
5. A `JwtTokenService` for issuing tokens after the application has authenticated a user.

The examples below show code blocks **without package or import statements**, as requested. Add the snippets to files in your consuming application's own source tree and add the required imports in your IDE. Each algorithm example is an alternative; configure only one per application instance.

## Shared servlet filter

Create a file such as `src/main/java/<your-package>/filter/MiniSecFilter.java`. This filter is the same for every algorithm. It maps MiniSec results to HTTP 200-chain continuation, 401, or 403 behavior. The processor manages its own `SecurityContextHolder` lifecycle; this filter does not attempt to preserve the context after `process()` returns.

public final class MiniSecFilter implements Filter {

    private final SecurityRequestProcessor processor;

    public MiniSecFilter(SecurityRequestProcessor processor) {
        this.processor = processor;
    }

    @Override
    public void doFilter(ServletRequest servletRequest,
                         ServletResponse servletResponse,
                         FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        SecurityRequest securityRequest = toSecurityRequest(request);
        SecurityResult result;

        try {
            result = processor.process(securityRequest);
        } catch (AuthenticationException ex) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
            return;
        }

        if (result.isAllowed()) {
            chain.doFilter(request, response);
            return;
        }
        if (result.isUnauthenticated()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
    }

    private SecurityRequest toSecurityRequest(HttpServletRequest request) {
        Map<String, String> headers = new HashMap<>();
        Enumeration<String> names = request.getHeaderNames();
        if (names != null) {
            while (names.hasMoreElements()) {
                String name = names.nextElement();
                headers.put(name, request.getHeader(name));
            }
        }
        return new SecurityRequest(request.getRequestURI(), request.getMethod(), headers);
    }
}

> **Integration note:** This filter only demonstrates authentication/authorization decisions and response mapping. If your controllers need to read an authenticated principal, design an explicit request-scoped handoff or framework adapter; `SecurityRequestProcessor.process()` clears MiniSec's thread-local context in its `finally` block.

## Choose one of the ten algorithm configurations

All configuration examples register the same authorization policy:

- `GET /api/public` — public.
- `POST /api/auth/login` — public, so a caller can obtain a token.
- `/api/user/**` — authenticated.
- `/api/admin/**` — requires the `ADMIN` authority.

Adjust these paths and authority names for your application. The authority values inside JWTs must match what your application checks. The examples use `sub` as the principal claim and `role` as the authorities claim.

Each configuration creates these beans:

- `JwtConfiguration` — configured algorithm and verification key.
- `JwtEncoder` — configured algorithm and signing key.
- `JwtTokenService` — example token lifetime of 15 minutes.
- `SecurityRequestProcessor` — authentication and authorization pipeline.
- `MiniSecFilter` and its servlet filter registration.

### Shared authorization and filter bean pattern

There are ten `JwtAlgorithm` enum options. EDDSA is one option, shown twice below because the library supports both Ed25519 and Ed448 key pairs. Each standalone configuration below includes the setup so it can be copied independently. Do not enable multiple configuration classes at the same time.

## Algorithm examples

### HS256

**Key requirement:** At least 32 decoded bytes.

Create `MiniSecHS256SecurityConfig.java` in your consuming application. This configuration is specific to `HS256`.

```java
@Configuration
public class MiniSecHS256SecurityConfig {

    @Value("${minisec.jwt.secret-base64}")
    private String secretBase64;

    @Bean
    SecretKey miniSecHS256Key() {
        return loadSecret(secretBase64);
    }

    @Bean
    JwtConfiguration jwtConfiguration(SecretKey key) {
        return new JwtConfiguration(JwtAlgorithm.HS256, key, "sub", "role");
    }

    @Bean
    JwtEncoder jwtEncoder(SecretKey key) {
        return new JjwtJwtEncoder(JwtAlgorithm.HS256, key);
    }

    @Bean
    JwtTokenService jwtTokenService(JwtEncoder encoder, JwtConfiguration config) {
        return new JwtTokenService(encoder, config, Duration.ofMinutes(15));
    }

    @Bean
    SecurityRequestProcessor securityRequestProcessor(JwtConfiguration config) {
        SecurityConfiguration security = new SecurityConfiguration();
        security.addAuthenticationConverter(new JwtAuthenticationConverter());
        security.addAuthenticationProvider(new JwtAuthenticationProviderFactory().create(config));
        security.authorizeHttpRequests()
                .permitAll("/api/public")
                .permitAll("/api/auth/login", "POST")
                .authenticated("/api/user/**")
                .hasAuthority("/api/admin/**", "ADMIN");
        return security.build();
    }

    @Bean
    MiniSecFilter miniSecFilter(SecurityRequestProcessor processor) {
        return new MiniSecFilter(processor);
    }

    @Bean
    FilterRegistrationBean<MiniSecFilter> miniSecFilterRegistration(MiniSecFilter filter) {
        FilterRegistrationBean<MiniSecFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.addUrlPatterns("/*");
        registration.setOrder(1);
        return registration;
    }

    private SecretKey loadSecret(String value) {
        try {
            return Keys.hmacShaKeyFor(Base64.getDecoder().decode(value));
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid Base64 or key too short for HS256", ex);
        }
    }
}
```

`application.yml` for HS256:

```yaml
minisec:
  jwt:
    algorithm: HS256
    secret-base64: "<BASE64_SECRET_HS256>"
```

### HS384

**Key requirement:** At least 48 decoded bytes.

Create `MiniSecHS384SecurityConfig.java` in your consuming application. This configuration is specific to `HS384`.

```java
@Configuration
public class MiniSecHS384SecurityConfig {

    @Value("${minisec.jwt.secret-base64}")
    private String secretBase64;

    @Bean
    SecretKey miniSecHS384Key() {
        return loadSecret(secretBase64);
    }

    @Bean
    JwtConfiguration jwtConfiguration(SecretKey key) {
        return new JwtConfiguration(JwtAlgorithm.HS384, key, "sub", "role");
    }

    @Bean
    JwtEncoder jwtEncoder(SecretKey key) {
        return new JjwtJwtEncoder(JwtAlgorithm.HS384, key);
    }

    @Bean
    JwtTokenService jwtTokenService(JwtEncoder encoder, JwtConfiguration config) {
        return new JwtTokenService(encoder, config, Duration.ofMinutes(15));
    }

    @Bean
    SecurityRequestProcessor securityRequestProcessor(JwtConfiguration config) {
        SecurityConfiguration security = new SecurityConfiguration();
        security.addAuthenticationConverter(new JwtAuthenticationConverter());
        security.addAuthenticationProvider(new JwtAuthenticationProviderFactory().create(config));
        security.authorizeHttpRequests()
                .permitAll("/api/public")
                .permitAll("/api/auth/login", "POST")
                .authenticated("/api/user/**")
                .hasAuthority("/api/admin/**", "ADMIN");
        return security.build();
    }

    @Bean
    MiniSecFilter miniSecFilter(SecurityRequestProcessor processor) {
        return new MiniSecFilter(processor);
    }

    @Bean
    FilterRegistrationBean<MiniSecFilter> miniSecFilterRegistration(MiniSecFilter filter) {
        FilterRegistrationBean<MiniSecFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.addUrlPatterns("/*");
        registration.setOrder(1);
        return registration;
    }

    private SecretKey loadSecret(String value) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(value));
            if (key.getEncoded().length < 48) throw new IllegalStateException("HS384 requires at least 48 decoded bytes");
            return key;
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid Base64 or key too short for HS384", ex);
        }
    }
}
```

`application.yml` for HS384:

```yaml
minisec:
  jwt:
    algorithm: HS384
    secret-base64: "<BASE64_SECRET_HS384>"
```

### HS512

**Key requirement:** At least 64 decoded bytes.

Create `MiniSecHS512SecurityConfig.java` in your consuming application. This configuration is specific to `HS512`.

```java
@Configuration
public class MiniSecHS512SecurityConfig {

    @Value("${minisec.jwt.secret-base64}")
    private String secretBase64;

    @Bean
    SecretKey miniSecHS512Key() {
        return loadSecret(secretBase64);
    }

    @Bean
    JwtConfiguration jwtConfiguration(SecretKey key) {
        return new JwtConfiguration(JwtAlgorithm.HS512, key, "sub", "role");
    }

    @Bean
    JwtEncoder jwtEncoder(SecretKey key) {
        return new JjwtJwtEncoder(JwtAlgorithm.HS512, key);
    }

    @Bean
    JwtTokenService jwtTokenService(JwtEncoder encoder, JwtConfiguration config) {
        return new JwtTokenService(encoder, config, Duration.ofMinutes(15));
    }

    @Bean
    SecurityRequestProcessor securityRequestProcessor(JwtConfiguration config) {
        SecurityConfiguration security = new SecurityConfiguration();
        security.addAuthenticationConverter(new JwtAuthenticationConverter());
        security.addAuthenticationProvider(new JwtAuthenticationProviderFactory().create(config));
        security.authorizeHttpRequests()
                .permitAll("/api/public")
                .permitAll("/api/auth/login", "POST")
                .authenticated("/api/user/**")
                .hasAuthority("/api/admin/**", "ADMIN");
        return security.build();
    }

    @Bean
    MiniSecFilter miniSecFilter(SecurityRequestProcessor processor) {
        return new MiniSecFilter(processor);
    }

    @Bean
    FilterRegistrationBean<MiniSecFilter> miniSecFilterRegistration(MiniSecFilter filter) {
        FilterRegistrationBean<MiniSecFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.addUrlPatterns("/*");
        registration.setOrder(1);
        return registration;
    }

    private SecretKey loadSecret(String value) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(value));
            if (key.getEncoded().length < 64) throw new IllegalStateException("HS512 requires at least 64 decoded bytes");
            return key;
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid Base64 or key too short for HS512", ex);
        }
    }
}
```

`application.yml` for HS512:

```yaml
minisec:
  jwt:
    algorithm: HS512
    secret-base64: "<BASE64_SECRET_HS512>"
```

### RS256

**Key requirement:** RSA private/public key pair; at least 2048 bits.

Create `MiniSecRS256SecurityConfig.java`. The private key signs tokens; the public key verifies them.

```java
@Configuration
public class MiniSecRS256SecurityConfig {

    @Value("${minisec.jwt.private-key-base64}")
    private String privateKeyBase64;

    @Value("${minisec.jwt.public-key-base64}")
    private String publicKeyBase64;

    @Bean
    PrivateKey miniSecSigningKey() {
        return loadPrivateKey(privateKeyBase64);
    }

    @Bean
    PublicKey miniSecVerificationKey() {
        return loadPublicKey(publicKeyBase64);
    }

    @Bean
    JwtConfiguration jwtConfiguration(PublicKey verificationKey) {
        return new JwtConfiguration(JwtAlgorithm.RS256, verificationKey, "sub", "role");
    }

    @Bean
    JwtEncoder jwtEncoder(PrivateKey signingKey) {
        return new JjwtJwtEncoder(JwtAlgorithm.RS256, signingKey);
    }

    @Bean
    JwtTokenService jwtTokenService(JwtEncoder encoder, JwtConfiguration config) {
        return new JwtTokenService(encoder, config, Duration.ofMinutes(15));
    }

    @Bean
    SecurityRequestProcessor securityRequestProcessor(JwtConfiguration config) {
        SecurityConfiguration security = new SecurityConfiguration();
        security.addAuthenticationConverter(new JwtAuthenticationConverter());
        security.addAuthenticationProvider(new JwtAuthenticationProviderFactory().create(config));
        security.authorizeHttpRequests()
                .permitAll("/api/public")
                .permitAll("/api/auth/login", "POST")
                .authenticated("/api/user/**")
                .hasAuthority("/api/admin/**", "ADMIN");
        return security.build();
    }

    @Bean
    MiniSecFilter miniSecFilter(SecurityRequestProcessor processor) {
        return new MiniSecFilter(processor);
    }

    @Bean
    FilterRegistrationBean<MiniSecFilter> miniSecFilterRegistration(MiniSecFilter filter) {
        FilterRegistrationBean<MiniSecFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.addUrlPatterns("/*");
        registration.setOrder(1);
        return registration;
    }

    private PrivateKey loadPrivateKey(String value) {
        try {
            byte[] der = Base64.getDecoder().decode(value);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid RS256 PKCS#8 private key", ex);
        }
    }

    private PublicKey loadPublicKey(String value) {
        try {
            byte[] der = Base64.getDecoder().decode(value);
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid RS256 X.509 public key", ex);
        }
    }
}
```

`application.yml` for RS256:

```yaml
minisec:
  jwt:
    algorithm: RS256
    private-key-base64: "<BASE64_PKCS8_PRIVATE_KEY>"
    public-key-base64: "<BASE64_X509_PUBLIC_KEY>"
```

### RS384

**Key requirement:** RSA private/public key pair; at least 2048 bits.

Create `MiniSecRS384SecurityConfig.java`. The private key signs tokens; the public key verifies them.

```java
@Configuration
public class MiniSecRS384SecurityConfig {

    @Value("${minisec.jwt.private-key-base64}")
    private String privateKeyBase64;

    @Value("${minisec.jwt.public-key-base64}")
    private String publicKeyBase64;

    @Bean
    PrivateKey miniSecSigningKey() {
        return loadPrivateKey(privateKeyBase64);
    }

    @Bean
    PublicKey miniSecVerificationKey() {
        return loadPublicKey(publicKeyBase64);
    }

    @Bean
    JwtConfiguration jwtConfiguration(PublicKey verificationKey) {
        return new JwtConfiguration(JwtAlgorithm.RS384, verificationKey, "sub", "role");
    }

    @Bean
    JwtEncoder jwtEncoder(PrivateKey signingKey) {
        return new JjwtJwtEncoder(JwtAlgorithm.RS384, signingKey);
    }

    @Bean
    JwtTokenService jwtTokenService(JwtEncoder encoder, JwtConfiguration config) {
        return new JwtTokenService(encoder, config, Duration.ofMinutes(15));
    }

    @Bean
    SecurityRequestProcessor securityRequestProcessor(JwtConfiguration config) {
        SecurityConfiguration security = new SecurityConfiguration();
        security.addAuthenticationConverter(new JwtAuthenticationConverter());
        security.addAuthenticationProvider(new JwtAuthenticationProviderFactory().create(config));
        security.authorizeHttpRequests()
                .permitAll("/api/public")
                .permitAll("/api/auth/login", "POST")
                .authenticated("/api/user/**")
                .hasAuthority("/api/admin/**", "ADMIN");
        return security.build();
    }

    @Bean
    MiniSecFilter miniSecFilter(SecurityRequestProcessor processor) {
        return new MiniSecFilter(processor);
    }

    @Bean
    FilterRegistrationBean<MiniSecFilter> miniSecFilterRegistration(MiniSecFilter filter) {
        FilterRegistrationBean<MiniSecFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.addUrlPatterns("/*");
        registration.setOrder(1);
        return registration;
    }

    private PrivateKey loadPrivateKey(String value) {
        try {
            byte[] der = Base64.getDecoder().decode(value);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid RS384 PKCS#8 private key", ex);
        }
    }

    private PublicKey loadPublicKey(String value) {
        try {
            byte[] der = Base64.getDecoder().decode(value);
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid RS384 X.509 public key", ex);
        }
    }
}
```

`application.yml` for RS384:

```yaml
minisec:
  jwt:
    algorithm: RS384
    private-key-base64: "<BASE64_PKCS8_PRIVATE_KEY>"
    public-key-base64: "<BASE64_X509_PUBLIC_KEY>"
```

### RS512

**Key requirement:** RSA private/public key pair; at least 2048 bits.

Create `MiniSecRS512SecurityConfig.java`. The private key signs tokens; the public key verifies them.

```java
@Configuration
public class MiniSecRS512SecurityConfig {

    @Value("${minisec.jwt.private-key-base64}")
    private String privateKeyBase64;

    @Value("${minisec.jwt.public-key-base64}")
    private String publicKeyBase64;

    @Bean
    PrivateKey miniSecSigningKey() {
        return loadPrivateKey(privateKeyBase64);
    }

    @Bean
    PublicKey miniSecVerificationKey() {
        return loadPublicKey(publicKeyBase64);
    }

    @Bean
    JwtConfiguration jwtConfiguration(PublicKey verificationKey) {
        return new JwtConfiguration(JwtAlgorithm.RS512, verificationKey, "sub", "role");
    }

    @Bean
    JwtEncoder jwtEncoder(PrivateKey signingKey) {
        return new JjwtJwtEncoder(JwtAlgorithm.RS512, signingKey);
    }

    @Bean
    JwtTokenService jwtTokenService(JwtEncoder encoder, JwtConfiguration config) {
        return new JwtTokenService(encoder, config, Duration.ofMinutes(15));
    }

    @Bean
    SecurityRequestProcessor securityRequestProcessor(JwtConfiguration config) {
        SecurityConfiguration security = new SecurityConfiguration();
        security.addAuthenticationConverter(new JwtAuthenticationConverter());
        security.addAuthenticationProvider(new JwtAuthenticationProviderFactory().create(config));
        security.authorizeHttpRequests()
                .permitAll("/api/public")
                .permitAll("/api/auth/login", "POST")
                .authenticated("/api/user/**")
                .hasAuthority("/api/admin/**", "ADMIN");
        return security.build();
    }

    @Bean
    MiniSecFilter miniSecFilter(SecurityRequestProcessor processor) {
        return new MiniSecFilter(processor);
    }

    @Bean
    FilterRegistrationBean<MiniSecFilter> miniSecFilterRegistration(MiniSecFilter filter) {
        FilterRegistrationBean<MiniSecFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.addUrlPatterns("/*");
        registration.setOrder(1);
        return registration;
    }

    private PrivateKey loadPrivateKey(String value) {
        try {
            byte[] der = Base64.getDecoder().decode(value);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid RS512 PKCS#8 private key", ex);
        }
    }

    private PublicKey loadPublicKey(String value) {
        try {
            byte[] der = Base64.getDecoder().decode(value);
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid RS512 X.509 public key", ex);
        }
    }
}
```

`application.yml` for RS512:

```yaml
minisec:
  jwt:
    algorithm: RS512
    private-key-base64: "<BASE64_PKCS8_PRIVATE_KEY>"
    public-key-base64: "<BASE64_X509_PUBLIC_KEY>"
```

### ES256

**Key requirement:** P-256 (secp256r1) key pair.

Create `MiniSecES256SecurityConfig.java`. The private key signs tokens; the public key verifies them.

```java
@Configuration
public class MiniSecES256SecurityConfig {

    @Value("${minisec.jwt.private-key-base64}")
    private String privateKeyBase64;

    @Value("${minisec.jwt.public-key-base64}")
    private String publicKeyBase64;

    @Bean
    PrivateKey miniSecSigningKey() {
        return loadPrivateKey(privateKeyBase64);
    }

    @Bean
    PublicKey miniSecVerificationKey() {
        return loadPublicKey(publicKeyBase64);
    }

    @Bean
    JwtConfiguration jwtConfiguration(PublicKey verificationKey) {
        return new JwtConfiguration(JwtAlgorithm.ES256, verificationKey, "sub", "role");
    }

    @Bean
    JwtEncoder jwtEncoder(PrivateKey signingKey) {
        return new JjwtJwtEncoder(JwtAlgorithm.ES256, signingKey);
    }

    @Bean
    JwtTokenService jwtTokenService(JwtEncoder encoder, JwtConfiguration config) {
        return new JwtTokenService(encoder, config, Duration.ofMinutes(15));
    }

    @Bean
    SecurityRequestProcessor securityRequestProcessor(JwtConfiguration config) {
        SecurityConfiguration security = new SecurityConfiguration();
        security.addAuthenticationConverter(new JwtAuthenticationConverter());
        security.addAuthenticationProvider(new JwtAuthenticationProviderFactory().create(config));
        security.authorizeHttpRequests()
                .permitAll("/api/public")
                .permitAll("/api/auth/login", "POST")
                .authenticated("/api/user/**")
                .hasAuthority("/api/admin/**", "ADMIN");
        return security.build();
    }

    @Bean
    MiniSecFilter miniSecFilter(SecurityRequestProcessor processor) {
        return new MiniSecFilter(processor);
    }

    @Bean
    FilterRegistrationBean<MiniSecFilter> miniSecFilterRegistration(MiniSecFilter filter) {
        FilterRegistrationBean<MiniSecFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.addUrlPatterns("/*");
        registration.setOrder(1);
        return registration;
    }

    private PrivateKey loadPrivateKey(String value) {
        try {
            byte[] der = Base64.getDecoder().decode(value);
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid ES256 PKCS#8 private key", ex);
        }
    }

    private PublicKey loadPublicKey(String value) {
        try {
            byte[] der = Base64.getDecoder().decode(value);
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid ES256 X.509 public key", ex);
        }
    }
}
```

`application.yml` for ES256:

```yaml
minisec:
  jwt:
    algorithm: ES256
    private-key-base64: "<BASE64_PKCS8_PRIVATE_KEY>"
    public-key-base64: "<BASE64_X509_PUBLIC_KEY>"
```

### ES384

**Key requirement:** P-384 (secp384r1) key pair.

Create `MiniSecES384SecurityConfig.java`. The private key signs tokens; the public key verifies them.

```java
@Configuration
public class MiniSecES384SecurityConfig {

    @Value("${minisec.jwt.private-key-base64}")
    private String privateKeyBase64;

    @Value("${minisec.jwt.public-key-base64}")
    private String publicKeyBase64;

    @Bean
    PrivateKey miniSecSigningKey() {
        return loadPrivateKey(privateKeyBase64);
    }

    @Bean
    PublicKey miniSecVerificationKey() {
        return loadPublicKey(publicKeyBase64);
    }

    @Bean
    JwtConfiguration jwtConfiguration(PublicKey verificationKey) {
        return new JwtConfiguration(JwtAlgorithm.ES384, verificationKey, "sub", "role");
    }

    @Bean
    JwtEncoder jwtEncoder(PrivateKey signingKey) {
        return new JjwtJwtEncoder(JwtAlgorithm.ES384, signingKey);
    }

    @Bean
    JwtTokenService jwtTokenService(JwtEncoder encoder, JwtConfiguration config) {
        return new JwtTokenService(encoder, config, Duration.ofMinutes(15));
    }

    @Bean
    SecurityRequestProcessor securityRequestProcessor(JwtConfiguration config) {
        SecurityConfiguration security = new SecurityConfiguration();
        security.addAuthenticationConverter(new JwtAuthenticationConverter());
        security.addAuthenticationProvider(new JwtAuthenticationProviderFactory().create(config));
        security.authorizeHttpRequests()
                .permitAll("/api/public")
                .permitAll("/api/auth/login", "POST")
                .authenticated("/api/user/**")
                .hasAuthority("/api/admin/**", "ADMIN");
        return security.build();
    }

    @Bean
    MiniSecFilter miniSecFilter(SecurityRequestProcessor processor) {
        return new MiniSecFilter(processor);
    }

    @Bean
    FilterRegistrationBean<MiniSecFilter> miniSecFilterRegistration(MiniSecFilter filter) {
        FilterRegistrationBean<MiniSecFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.addUrlPatterns("/*");
        registration.setOrder(1);
        return registration;
    }

    private PrivateKey loadPrivateKey(String value) {
        try {
            byte[] der = Base64.getDecoder().decode(value);
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid ES384 PKCS#8 private key", ex);
        }
    }

    private PublicKey loadPublicKey(String value) {
        try {
            byte[] der = Base64.getDecoder().decode(value);
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid ES384 X.509 public key", ex);
        }
    }
}
```

`application.yml` for ES384:

```yaml
minisec:
  jwt:
    algorithm: ES384
    private-key-base64: "<BASE64_PKCS8_PRIVATE_KEY>"
    public-key-base64: "<BASE64_X509_PUBLIC_KEY>"
```

### ES512

**Key requirement:** P-521 (secp521r1) key pair.

Create `MiniSecES512SecurityConfig.java`. The private key signs tokens; the public key verifies them.

```java
@Configuration
public class MiniSecES512SecurityConfig {

    @Value("${minisec.jwt.private-key-base64}")
    private String privateKeyBase64;

    @Value("${minisec.jwt.public-key-base64}")
    private String publicKeyBase64;

    @Bean
    PrivateKey miniSecSigningKey() {
        return loadPrivateKey(privateKeyBase64);
    }

    @Bean
    PublicKey miniSecVerificationKey() {
        return loadPublicKey(publicKeyBase64);
    }

    @Bean
    JwtConfiguration jwtConfiguration(PublicKey verificationKey) {
        return new JwtConfiguration(JwtAlgorithm.ES512, verificationKey, "sub", "role");
    }

    @Bean
    JwtEncoder jwtEncoder(PrivateKey signingKey) {
        return new JjwtJwtEncoder(JwtAlgorithm.ES512, signingKey);
    }

    @Bean
    JwtTokenService jwtTokenService(JwtEncoder encoder, JwtConfiguration config) {
        return new JwtTokenService(encoder, config, Duration.ofMinutes(15));
    }

    @Bean
    SecurityRequestProcessor securityRequestProcessor(JwtConfiguration config) {
        SecurityConfiguration security = new SecurityConfiguration();
        security.addAuthenticationConverter(new JwtAuthenticationConverter());
        security.addAuthenticationProvider(new JwtAuthenticationProviderFactory().create(config));
        security.authorizeHttpRequests()
                .permitAll("/api/public")
                .permitAll("/api/auth/login", "POST")
                .authenticated("/api/user/**")
                .hasAuthority("/api/admin/**", "ADMIN");
        return security.build();
    }

    @Bean
    MiniSecFilter miniSecFilter(SecurityRequestProcessor processor) {
        return new MiniSecFilter(processor);
    }

    @Bean
    FilterRegistrationBean<MiniSecFilter> miniSecFilterRegistration(MiniSecFilter filter) {
        FilterRegistrationBean<MiniSecFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.addUrlPatterns("/*");
        registration.setOrder(1);
        return registration;
    }

    private PrivateKey loadPrivateKey(String value) {
        try {
            byte[] der = Base64.getDecoder().decode(value);
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid ES512 PKCS#8 private key", ex);
        }
    }

    private PublicKey loadPublicKey(String value) {
        try {
            byte[] der = Base64.getDecoder().decode(value);
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid ES512 X.509 public key", ex);
        }
    }
}
```

`application.yml` for ES512:

```yaml
minisec:
  jwt:
    algorithm: ES512
    private-key-base64: "<BASE64_PKCS8_PRIVATE_KEY>"
    public-key-base64: "<BASE64_X509_PUBLIC_KEY>"
```

### EDDSA ED25519

**Key requirement:** Ed25519 key pair.

Create `MiniSecEDDSAED25519SecurityConfig.java`. The private key signs tokens; the public key verifies them.

```java
@Configuration
public class MiniSecEDDSAED25519SecurityConfig {

    @Value("${minisec.jwt.private-key-base64}")
    private String privateKeyBase64;

    @Value("${minisec.jwt.public-key-base64}")
    private String publicKeyBase64;
    @Value("${minisec.jwt.eddsa-curve}")
    private String eddsaCurve;


    @Bean
    PrivateKey miniSecSigningKey() {
        validateConfiguredCurve();
        return loadPrivateKey(privateKeyBase64);
    }

    @Bean
    PublicKey miniSecVerificationKey() {
        validateConfiguredCurve();
        return loadPublicKey(publicKeyBase64);
    }

    @Bean
    JwtConfiguration jwtConfiguration(PublicKey verificationKey) {
        return new JwtConfiguration(JwtAlgorithm.EDDSA, verificationKey, "sub", "role");
    }

    @Bean
    JwtEncoder jwtEncoder(PrivateKey signingKey) {
        return new JjwtJwtEncoder(JwtAlgorithm.EDDSA, signingKey);
    }

    @Bean
    JwtTokenService jwtTokenService(JwtEncoder encoder, JwtConfiguration config) {
        return new JwtTokenService(encoder, config, Duration.ofMinutes(15));
    }

    @Bean
    SecurityRequestProcessor securityRequestProcessor(JwtConfiguration config) {
        SecurityConfiguration security = new SecurityConfiguration();
        security.addAuthenticationConverter(new JwtAuthenticationConverter());
        security.addAuthenticationProvider(new JwtAuthenticationProviderFactory().create(config));
        security.authorizeHttpRequests()
                .permitAll("/api/public")
                .permitAll("/api/auth/login", "POST")
                .authenticated("/api/user/**")
                .hasAuthority("/api/admin/**", "ADMIN");
        return security.build();
    }

    @Bean
    MiniSecFilter miniSecFilter(SecurityRequestProcessor processor) {
        return new MiniSecFilter(processor);
    }

    @Bean
    FilterRegistrationBean<MiniSecFilter> miniSecFilterRegistration(MiniSecFilter filter) {
        FilterRegistrationBean<MiniSecFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.addUrlPatterns("/*");
        registration.setOrder(1);
        return registration;
    }

    private void validateConfiguredCurve() {
        if (!"Ed25519".equalsIgnoreCase(eddsaCurve)) {
            throw new IllegalStateException("minisec.jwt.eddsa-curve must be Ed25519 for this configuration");
        }
    }

    private PrivateKey loadPrivateKey(String value) {
        try {
            byte[] der = Base64.getDecoder().decode(value);
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid EDDSA ED25519 PKCS#8 private key", ex);
        }
    }

    private PublicKey loadPublicKey(String value) {
        try {
            byte[] der = Base64.getDecoder().decode(value);
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid EDDSA ED25519 X.509 public key", ex);
        }
    }
}
```

`application.yml` for EDDSA ED25519:

```yaml
minisec:
  jwt:
    algorithm: EDDSA
    eddsa-curve: Ed25519
    private-key-base64: "<BASE64_PKCS8_PRIVATE_KEY>"
    public-key-base64: "<BASE64_X509_PUBLIC_KEY>"
```

### EDDSA ED448

**Key requirement:** Ed448 key pair.

Create `MiniSecEDDSAED448SecurityConfig.java`. The private key signs tokens; the public key verifies them.

```java
@Configuration
public class MiniSecEDDSAED448SecurityConfig {

    @Value("${minisec.jwt.private-key-base64}")
    private String privateKeyBase64;

    @Value("${minisec.jwt.public-key-base64}")
    private String publicKeyBase64;
    @Value("${minisec.jwt.eddsa-curve}")
    private String eddsaCurve;


    @Bean
    PrivateKey miniSecSigningKey() {
        validateConfiguredCurve();
        return loadPrivateKey(privateKeyBase64);
    }

    @Bean
    PublicKey miniSecVerificationKey() {
        validateConfiguredCurve();
        return loadPublicKey(publicKeyBase64);
    }

    @Bean
    JwtConfiguration jwtConfiguration(PublicKey verificationKey) {
        return new JwtConfiguration(JwtAlgorithm.EDDSA, verificationKey, "sub", "role");
    }

    @Bean
    JwtEncoder jwtEncoder(PrivateKey signingKey) {
        return new JjwtJwtEncoder(JwtAlgorithm.EDDSA, signingKey);
    }

    @Bean
    JwtTokenService jwtTokenService(JwtEncoder encoder, JwtConfiguration config) {
        return new JwtTokenService(encoder, config, Duration.ofMinutes(15));
    }

    @Bean
    SecurityRequestProcessor securityRequestProcessor(JwtConfiguration config) {
        SecurityConfiguration security = new SecurityConfiguration();
        security.addAuthenticationConverter(new JwtAuthenticationConverter());
        security.addAuthenticationProvider(new JwtAuthenticationProviderFactory().create(config));
        security.authorizeHttpRequests()
                .permitAll("/api/public")
                .permitAll("/api/auth/login", "POST")
                .authenticated("/api/user/**")
                .hasAuthority("/api/admin/**", "ADMIN");
        return security.build();
    }

    @Bean
    MiniSecFilter miniSecFilter(SecurityRequestProcessor processor) {
        return new MiniSecFilter(processor);
    }

    @Bean
    FilterRegistrationBean<MiniSecFilter> miniSecFilterRegistration(MiniSecFilter filter) {
        FilterRegistrationBean<MiniSecFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.addUrlPatterns("/*");
        registration.setOrder(1);
        return registration;
    }

    private void validateConfiguredCurve() {
        if (!"Ed448".equalsIgnoreCase(eddsaCurve)) {
            throw new IllegalStateException("minisec.jwt.eddsa-curve must be Ed448 for this configuration");
        }
    }

    private PrivateKey loadPrivateKey(String value) {
        try {
            byte[] der = Base64.getDecoder().decode(value);
            return KeyFactory.getInstance("Ed448").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid EDDSA ED448 PKCS#8 private key", ex);
        }
    }

    private PublicKey loadPublicKey(String value) {
        try {
            byte[] der = Base64.getDecoder().decode(value);
            return KeyFactory.getInstance("Ed448").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid EDDSA ED448 X.509 public key", ex);
        }
    }
}
```

`application.yml` for EDDSA ED448:

```yaml
minisec:
  jwt:
    algorithm: EDDSA
    eddsa-curve: Ed448
    private-key-base64: "<BASE64_PKCS8_PRIVATE_KEY>"
    public-key-base64: "<BASE64_X509_PUBLIC_KEY>"
```

## Key formats

- `secret-base64` is a Base64-encoded random HMAC secret. The minimum is checked by MiniSec's key validator; the YAML notes above state the minimum decoded byte lengths.
- `private-key-base64` must be Base64-encoded DER in PKCS#8 format.
- `public-key-base64` must be Base64-encoded DER in X.509 SubjectPublicKeyInfo format.
- RSA requires a matching RSA key pair of at least 2048 bits.
- ES256 requires P-256, ES384 requires P-384, and ES512 requires P-521.
- EDDSA uses either an Ed25519 or Ed448 key pair. The configured curve and key pair must match.

The placeholders in the examples are not usable keys. Generate test keys for local development, and keep production key material in a secure secret store rather than source control.

## Expected authorization behavior

| Request | Expected result |
|---|---|
| Public route without a token | Allowed by authorization policy |
| Protected route without a token | HTTP 401 |
| Protected route with a valid token and sufficient authority | Allowed |
| Protected route with malformed, expired, tampered, or wrong-algorithm token | HTTP 401 |
| Admin route with a valid token lacking `ADMIN` authority | HTTP 403 |

A public authorization rule does not necessarily mean an invalid bearer token is ignored. MiniSec's current processor attempts authentication when a bearer token is supplied, before evaluating authorization rules; a malformed or invalid token can therefore be rejected even on a public route.

## Security notes and current limitations

- The examples are integration templates and have not been compiled as a consuming application here. Confirm imports, dependency versions, endpoint mappings, and configuration against your own application.
- The example claim names (`sub` and `role`) must match the claims issued by your token-generation flow. The authorities claim is expected to be in the structure handled by `DefaultJwtAuthoritiesExtractor`.
- These snippets show token infrastructure and authorization rules; they do not implement user registration, database-backed login, password hashing, or credential storage. Your application must authenticate users safely before calling `JwtTokenService.generateToken()`.
- The current processor clears `SecurityContextHolder` at the end of processing. Do not assume the context remains available inside a controller after the filter returns from `process()`; build an explicit request-scoped handoff if your application requires controller-level principal access.
- There is no claim here that MiniSec has been published to Maven Central. Current `1.0-SNAPSHOT` artifacts are intended for local development.
- Do not expose signing keys, raw JWTs, or passwords in logs. Use HTTPS in deployed applications.

## Future improvements

Potential future work (not claimed as currently implemented):

1. Database-backed user authentication and authority loading in a consuming application.
2. Key rotation and a managed verification-key lifecycle.
3. Optional issuer and audience validation.
4. Framework adapters beyond the servlet integration example.
5. More end-to-end tests for application integration, configuration errors, and concurrent requests.
6. Expanded documentation, runnable examples, and release/versioning guidance.
7. Additional operational guidance for key management and safe diagnostics.




