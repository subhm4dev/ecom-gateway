package com.ecom.gateway.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * JWT Validation Service
 *
 * <p>Validates JWT tokens, extracts claims, and checks expiry.
 * Works with JwksService to get public keys for signature verification.
 */
@Service
public class JwtValidationService {

    private static final Logger log = LoggerFactory.getLogger(JwtValidationService.class);
    private final JwksService jwksService;

    public JwtValidationService(JwksService jwksService) {
        this.jwksService = jwksService;
    }

    /**
     * Validate JWT token and extract claims
     *
     * @param token JWT token string
     * @return Mono<JWTClaimsSet> with validated claims
     * @throws IllegalArgumentException if token is invalid or expired
     */
    public Mono<JWTClaimsSet> validateToken(String token) {
        if (token == null || token.isBlank()) {
            return Mono.error(new IllegalArgumentException("Token is required"));
        }

        try {
            // Parse JWT token
            SignedJWT signedJWT = SignedJWT.parse(token);

            // Extract Key ID from header
            String kid = signedJWT.getHeader().getKeyID();
            if (kid == null) {
                return Mono.error(new IllegalArgumentException("JWT token missing Key ID (kid)"));
            }

            // Get public key from JWKS cache (reactive)
            return jwksService.getPublicKey(kid)
                .flatMap(publicKey -> {
                    try {
                        // Verify signature
                        JWSVerifier verifier = new RSASSAVerifier(publicKey);
                        if (!signedJWT.verify(verifier)) {
                            return Mono.error(new IllegalArgumentException("Invalid JWT signature"));
                        }

                        // Get claims
                        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

                        // Check expiry
                        Date expirationTime = claimsSet.getExpirationTime();
                        if (expirationTime != null && expirationTime.before(Date.from(Instant.now()))) {
                            return Mono.error(new IllegalArgumentException("JWT token has expired"));
                        }

                        // Check issuer
                        String issuer = claimsSet.getIssuer();
                        if (issuer != null && !issuer.equals("ecom-identity")) {
                            log.warn("JWT token from unexpected issuer: {}", issuer);
                        }

                        return Mono.just(claimsSet);
                    } catch (JOSEException e) {
                        log.error("JOSE error during token validation", e);
                        return Mono.error(new IllegalArgumentException("JWT signature verification failed", e));
                    }
                });

        } catch (ParseException e) {
            log.error("Failed to parse JWT token", e);
            return Mono.error(new IllegalArgumentException("Invalid JWT token format", e));
        } catch (Exception e) {
            log.error("Unexpected error during token validation", e);
            return Mono.error(new IllegalArgumentException("Token validation failed", e));
        }
    }

    /**
     * Extract token ID (jti) from token
     * Used for blacklist checking
     */
    public String extractTokenId(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet().getJWTID();
        } catch (Exception e) {
            log.error("Failed to extract token ID", e);
            // Fallback: use token hash
            return String.valueOf(token.hashCode());
        }
    }

    /**
     * Extract user ID from token claims
     */
    public String extractUserId(JWTClaimsSet claims) {
        // Try userId claim first, fallback to subject
        String userId = claims.getClaim("userId") != null
            ? claims.getClaim("userId").toString()
            : claims.getSubject();

        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("JWT token missing user ID");
        }

        return userId;
    }

    /**
     * Extract tenant ID from token claims
     */
    public String extractTenantId(JWTClaimsSet claims) {
        Object tenantIdObj = claims.getClaim("tenantId");
        if (tenantIdObj == null) {
            throw new IllegalArgumentException("JWT token missing tenant ID");
        }
        return tenantIdObj.toString();
    }

    /**
     * Extract roles from token claims
     */
    @SuppressWarnings("unchecked")
    public List<String> extractRoles(JWTClaimsSet claims) {
        Object rolesObj = claims.getClaim("roles");
        if (rolesObj instanceof List) {
            return (List<String>) rolesObj;
        }
        return List.of(); // Return empty list if no roles
    }
}

