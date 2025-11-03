package com.ecom.gateway.service;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * JWKS Service
 * 
 * <p>Fetches and caches JSON Web Key Set (JWKS) from Identity service.
 * Periodically refreshes keys to support key rotation.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class JwksService {

    private final WebClient webClient;
    
    private final Map<String, RSAKey> jwkCache = new ConcurrentHashMap<>();
    
    @Value("${gateway.jwt.jwks-endpoint:/.well-known/jwks.json}")
    private String jwksEndpoint;
    
    private volatile long lastFetchTime = 0;

    /**
     * Get public key by Key ID (kid)
     * 
     * @param kid Key ID from JWT header
     * @return RSA public key
     * @throws IllegalArgumentException if key not found
     */
    public RSAKey getPublicKey(String kid) {
        RSAKey key = jwkCache.get(kid);
        if (key == null) {
            // Cache miss - refresh and try again
            log.warn("JWK key not found in cache: kid={}, refreshing cache...", kid);
            refreshJwksCache().block(Duration.ofSeconds(5));
            key = jwkCache.get(kid);
            if (key == null) {
                throw new IllegalArgumentException("JWK key not found: " + kid);
            }
        }
        return key;
    }

    /**
     * Refresh JWKS cache from Identity service
     */
    @Scheduled(fixedDelayString = "${gateway.jwt.jwks-cache-refresh-interval:PT5M}")
    public Mono<Void> refreshJwksCache() {
        log.debug("Refreshing JWKS cache from Identity service...");
        
        return webClient.get()
            .uri(jwksEndpoint)
            .retrieve()
            .bodyToMono(String.class)
            .doOnNext(response -> {
                try {
                    JWKSet jwkSet = JWKSet.parse(response);
                    Map<String, RSAKey> newCache = new ConcurrentHashMap<>();
                    
                    for (JWK jwk : jwkSet.getKeys()) {
                        if (jwk instanceof RSAKey) {
                            RSAKey rsaKey = (RSAKey) jwk;
                            newCache.put(rsaKey.getKeyID(), rsaKey);
                            log.debug("Cached JWK: kid={}", rsaKey.getKeyID());
                        }
                    }
                    
                    jwkCache.clear();
                    jwkCache.putAll(newCache);
                    lastFetchTime = System.currentTimeMillis();
                    
                    log.info("JWKS cache refreshed: {} keys cached", jwkCache.size());
                    
                } catch (ParseException e) {
                    log.error("Failed to parse JWKS response from Identity service", e);
                }
            })
            .doOnError(error -> {
                log.error("Failed to fetch JWKS from Identity service: {}", error.getMessage());
                // Don't clear cache on error - use stale keys
            })
            .then();
    }

    /**
     * Initialize cache on startup
     */
    @org.springframework.context.event.EventListener(org.springframework.boot.context.event.ApplicationReadyEvent.class)
    public void initializeCache() {
        log.info("Initializing JWKS cache...");
        refreshJwksCache().block(Duration.ofSeconds(10));
    }

    /**
     * Get cache statistics
     */
    public Map<String, Object> getCacheStats() {
        return Map.of(
            "cachedKeys", jwkCache.size(),
            "lastFetchTime", lastFetchTime
        );
    }
}

