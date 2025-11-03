package com.ecom.gateway.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
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
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);
    private final ReactiveRedisTemplate<String, String> redisTemplate;

    public SessionService(@Qualifier("reactiveRedisTemplate") ReactiveRedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }
    
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

