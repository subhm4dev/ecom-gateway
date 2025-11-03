package com.ecom.gateway.filter;

import com.ecom.gateway.config.GatewayConfig;
import com.ecom.gateway.service.JwtValidationService;
import com.ecom.gateway.service.SessionService;
import com.ecom.gateway.util.PublicPathMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.StringJoiner;

/**
 * JWT Authentication Filter
 * 
 * <p>Global filter that validates JWT tokens for all requests (except public paths).
 * Extracts user context and forwards it to downstream services via headers.
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    
    private final JwtValidationService jwtValidationService;
    private final SessionService sessionService;
    private final PublicPathMatcher publicPathMatcher;

    public JwtAuthenticationFilter(
            JwtValidationService jwtValidationService,
            SessionService sessionService,
            GatewayConfig gatewayConfig) {
        this.jwtValidationService = jwtValidationService;
        this.sessionService = sessionService;
        this.publicPathMatcher = new PublicPathMatcher(gatewayConfig.getPublicPaths());
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // 1. Check if path is public (skip validation)
        if (publicPathMatcher.isPublicPath(path)) {
            log.debug("Public path, skipping JWT validation: {}", path);
            return chain.filter(exchange);
        }

        // 2. Extract JWT token from Authorization header
        String authorization = request.getHeaders().getFirst("Authorization");
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            log.warn("Missing or invalid Authorization header: path={}", path);
            return handleUnauthorized(exchange, "Missing or invalid Authorization header");
        }

        String token = authorization.substring(7); // Remove "Bearer " prefix

        // 3. Extract token ID for blacklist check
        String tokenId = jwtValidationService.extractTokenId(token);

        // 4. Check Redis blacklist (fast fail)
        return sessionService.isTokenBlacklisted(tokenId)
            .flatMap(blacklisted -> {
                if (blacklisted) {
                    log.warn("Token is blacklisted: tokenId={}, path={}", tokenId, path);
                    return handleUnauthorized(exchange, "Token has been revoked");
                }

                // 5. Validate token (signature, expiry)
                return jwtValidationService.validateToken(token)
                    .flatMap(claims -> {
                        // 6. Extract user context
                        String userId = jwtValidationService.extractUserId(claims);
                        String tenantId = jwtValidationService.extractTenantId(claims);
                        List<String> roles = jwtValidationService.extractRoles(claims);

                        log.debug("Token validated successfully: userId={}, tenantId={}, path={}", 
                            userId, tenantId, path);

                        // 7. Add headers for downstream services
                        ServerHttpRequest modifiedRequest = request.mutate()
                            .header("X-User-Id", userId)
                            .header("X-Tenant-Id", tenantId)
                            .header("X-Roles", joinRoles(roles))
                            .build();

                        // 8. Continue with modified request
                        return chain.filter(exchange.mutate().request(modifiedRequest).build());
                    })
                    .onErrorResume(IllegalArgumentException.class, error -> {
                        log.warn("Token validation failed: path={}, error={}", path, error.getMessage());
                        return handleUnauthorized(exchange, error.getMessage());
                    });
            });
    }

    /**
     * Join roles list into comma-separated string
     */
    private String joinRoles(List<String> roles) {
        if (roles == null || roles.isEmpty()) {
            return "";
        }
        StringJoiner joiner = new StringJoiner(",");
        roles.forEach(joiner::add);
        return joiner.toString();
    }

    /**
     * Handle unauthorized request
     */
    private Mono<Void> handleUnauthorized(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().add("Content-Type", "application/json");
        
        String errorBody = String.format(
            "{\"error\":\"UNAUTHORIZED\",\"message\":\"%s\"}", 
            message.replace("\"", "\\\"")
        );
        
        byte[] errorBytes = errorBody.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return response.writeWith(
            Mono.just(response.bufferFactory().wrap(errorBytes))
        );
    }

    @Override
    public int getOrder() {
        // High precedence - run before other filters
        return -100;
    }
}

