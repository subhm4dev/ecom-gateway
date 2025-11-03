package com.ecom.gateway.service;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
public class JwksService {

    private static final Logger log = LoggerFactory.getLogger(JwksService.class);
    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    public JwksService(WebClient webClient) {
        this.webClient = webClient;
        this.objectMapper = new ObjectMapper();
    }
    
    private final Map<String, RSAKey> jwkCache = new ConcurrentHashMap<>();
    
    @Value("${gateway.jwt.jwks-endpoint:/.well-known/jwks.json}")
    private String jwksEndpoint;
    
    private volatile long lastFetchTime = 0;

    /**
     * Get public key by Key ID (kid)
     * 
     * @param kid Key ID from JWT header
     * @return Mono<RSAKey> with the public key
     * @throws IllegalArgumentException if key not found
     */
    public Mono<RSAKey> getPublicKey(String kid) {
        RSAKey key = jwkCache.get(kid);
        if (key != null) {
            return Mono.just(key);
        }
        
        // Cache miss - refresh and try again
        log.warn("JWK key not found in cache: kid={}, refreshing cache...", kid);
        return refreshJwksCache()
            .then(Mono.fromCallable(() -> {
                RSAKey refreshedKey = jwkCache.get(kid);
                if (refreshedKey == null) {
                    throw new IllegalArgumentException("JWK key not found after refresh: " + kid);
                }
                return refreshedKey;
            }));
    }

    /**
     * Refresh JWKS cache from Identity service
     * 
     * Note: @Scheduled uses fixedDelay in milliseconds. 
     * Configuration value should be in milliseconds (e.g., 300000 for 5 minutes)
     */
    @Scheduled(fixedDelayString = "${gateway.jwt.jwks-cache-refresh-interval-ms:300000}")
    public Mono<Void> refreshJwksCache() {
        log.debug("Refreshing JWKS cache from Identity service...");
        
        return webClient.get()
            .uri(jwksEndpoint)
            .retrieve()
            .bodyToMono(String.class)
            .doOnNext(response -> {
                try {
                    // Identity service wraps JWKS in standard response format: {"success": true, "data": {"keys": [...]}}
                    // Extract the "data" object which contains the actual JWKS
                    String jwksJson = extractJwksFromResponse(response);
                    
                    JWKSet jwkSet = JWKSet.parse(jwksJson);
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
                } catch (Exception e) {
                    log.error("Failed to process JWKS response from Identity service", e);
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
     * Extract JWKS JSON from Identity service's wrapped response
     * 
     * Identity service uses standard-response-starter which wraps responses as:
     * {"success": true, "data": {"keys": [...]}, ...}
     * 
     * This method extracts just the "data" part which contains the actual JWKS.
     */
    private String extractJwksFromResponse(String response) throws Exception {
        try {
            JsonNode rootNode = objectMapper.readTree(response);
            
            // Check if response is wrapped in standard format
            if (rootNode.has("data") && rootNode.get("data").has("keys")) {
                // Extract just the "data" object which is the JWKS
                JsonNode dataNode = rootNode.get("data");
                return objectMapper.writeValueAsString(dataNode);
            }
            
            // If not wrapped, assume it's already in JWKS format
            return response;
        } catch (Exception e) {
            log.warn("Failed to parse response as JSON, assuming raw JWKS format: {}", e.getMessage());
            // If parsing fails, assume it's already in raw JWKS format
            return response;
        }
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

