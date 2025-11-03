package com.ecom.gateway.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Session Service (Reactive)
 * 
 * <p>Checks token blacklist in Redis for logged-out tokens.
 * Uses reactive Redis for WebFlux compatibility.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class SessionService {

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    
    private static final String BLACKLIST_PREFIX = "jwt:blacklist:";

    /**
     * Check if a token is blacklisted
     * 
     * @param tokenId JWT ID (jti) from token
     * @return Mono<Boolean> true if blacklisted, false otherwise
     */
    public Mono<Boolean> isTokenBlacklisted(String tokenId) {
        if (tokenId == null || tokenId.isBlank()) {
            return Mono.just(false);
        }
        
        String key = BLACKLIST_PREFIX + tokenId;
        
        return redisTemplate.hasKey(key)
            .doOnNext(blacklisted -> {
                if (blacklisted) {
                    log.debug("Token blacklisted: tokenId={}", tokenId);
                }
            })
            .onErrorResume(error -> {
                log.error("Error checking token blacklist: tokenId={}, error={}", 
                    tokenId, error.getMessage());
                // If Redis is unavailable, allow request (fail open)
                // In production, you might want to fail closed for security
                return Mono.just(false);
            });
    }
}

