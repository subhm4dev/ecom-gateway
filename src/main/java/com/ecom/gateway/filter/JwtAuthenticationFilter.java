package com.ecom.gateway.filter;

import com.ecom.gateway.config.GatewayConfig;
import com.ecom.jwt.reactive.ReactiveJwtValidationService;
import com.ecom.gateway.util.PublicPathMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
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
 * <p><b>WHAT THIS DOES:</b>
 * This filter validates JWT tokens for all requests (except public paths) and extracts
 * user context to forward to downstream services. It supports a hybrid authentication
 * approach: reading tokens from either Authorization header OR cookies.
 * 
 * <p><b>HOW IT WORKS:</b>
 * 1. Checks if path is public (skip validation for auth endpoints, JWKS, etc.)
 * 2. Extracts JWT token from Authorization header (priority) OR cookies (fallback)
 * 3. Validates token (signature, expiry, blacklist check)
 * 4. Extracts user context (userId, tenantId, roles) from validated token
 * 5. Forwards token in Authorization header to downstream services
 * 6. Adds X-User-Id, X-Tenant-Id, X-Roles headers for convenience/logging
 * 
 * <p><b>WHY WE NEED THIS:</b>
 * - <b>Security:</b> Validates tokens before allowing access to protected resources
 * - <b>Hybrid Approach:</b> Supports both web (cookies) and mobile (Authorization header)
 * - <b>Context Propagation:</b> Extracts user info and forwards to downstream services
 * - <b>Single Entry Point:</b> Gateway validates once, services trust the forwarded token
 * 
 * <p><b>REAL-WORLD SCENARIOS THIS HANDLES:</b>
 * 
 * <b>Scenario 1: Web browser request (cookies)</b>
 * - User logs in → Backend sets httpOnly cookies
 * - Browser automatically sends cookies with next request
 * - Gateway reads token from cookie → Validates → Forwards in Authorization header
 * - Downstream services receive token in Authorization header (standard)
 * 
 * <b>Scenario 2: Mobile app request (Authorization header)</b>
 * - Mobile app stores tokens in Keychain/Keystore
 * - App sends token in Authorization header
 * - Gateway reads token from header → Validates → Forwards in Authorization header
 * - Downstream services receive token in Authorization header (standard)
 * 
 * <b>Scenario 3: Backward compatibility</b>
 * - Existing clients send token in Authorization header
 * - Gateway reads from header (priority) → Works as before
 * - No breaking changes for existing clients
 * 
 * <b>Scenario 4: Token validation failure</b>
 * - Token expired → Gateway returns 401 → Client must refresh token
 * - Token blacklisted (logout) → Gateway returns 401 → Client must re-login
 * - Invalid signature → Gateway returns 401 → Security breach detected
 * 
 * <b>Scenario 5: Public path (no validation)</b>
 * - Request to /api/v1/auth/login → Public path → Skip validation
 * - Request to /.well-known/jwks.json → Public path → Skip validation
 * - Request to /actuator/health → Public path → Skip validation
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    
    // Cookie name for access token (matches IAM service CookieService)
    private static final String ACCESS_TOKEN_COOKIE_NAME = "accessToken";
    
    private final ReactiveJwtValidationService jwtValidationService;
    private final PublicPathMatcher publicPathMatcher;

    public JwtAuthenticationFilter(
            ReactiveJwtValidationService jwtValidationService,
            GatewayConfig gatewayConfig) {
        this.jwtValidationService = jwtValidationService;
        this.publicPathMatcher = new PublicPathMatcher(gatewayConfig.getPublicPaths());
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // 1. Check if path is public (skip validation)
        // WHAT: Public paths don't require authentication (login, register, JWKS, health checks)
        // HOW: PublicPathMatcher checks if path matches configured public patterns
        // WHY: Auth endpoints need to be accessible without tokens (chicken-and-egg problem)
        // REAL-WORLD: User visits /api/v1/auth/login → No token needed → Can authenticate
        if (publicPathMatcher.isPublicPath(path)) {
            log.debug("Public path, skipping JWT validation: {}", path);
            return chain.filter(exchange);
        }

        // 2. Extract JWT token from Authorization header OR cookies (hybrid approach)
        // WHAT: Tries Authorization header first (mobile apps), then cookies (web browsers)
        // HOW: extractToken() helper method checks both sources
        // WHY: Supports both web (cookies) and mobile (header) clients with same API
        // REAL-WORLD: Web browser sends cookies → Gateway reads cookie → Mobile app sends header → Gateway reads header
        String token = extractToken(request);
        if (token == null) {
            log.warn("Missing JWT token: path={} (checked Authorization header and cookies)", path);
            return handleUnauthorized(exchange, "Missing or invalid authentication token");
        }

        // 3. Validate token (signature, expiry, blacklist)
        // WHAT: Validates token signature, checks expiry, verifies not blacklisted
        // HOW: ReactiveJwtValidationService uses JWKS to verify signature, checks Redis for blacklist
        // WHY: Ensures token is valid, not expired, and not revoked (logout)
        // REAL-WORLD: Token valid → Request proceeds → Token expired → 401 error → Client refreshes token
        // NOTE: Shared library handles blacklist check internally
        return jwtValidationService.validateToken(token)
            .flatMap(claims -> {
                // 4. Extract user context from validated token claims
                // WHAT: Gets userId, tenantId, and roles from JWT claims
                // HOW: ReactiveJwtValidationService extracts claims from validated token
                // WHY: Downstream services need user context for authorization and data filtering
                // REAL-WORLD: User requests /api/v1/catalog/products → Gateway extracts userId → 
                //            Forwards to catalog service → Service filters products by tenantId
                String userId = jwtValidationService.extractUserId(claims);
                String tenantId = jwtValidationService.extractTenantId(claims);
                List<String> roles = jwtValidationService.extractRoles(claims);

                log.debug("Token validated successfully: userId={}, tenantId={}, path={}", 
                    userId, tenantId, path);

                // 5. Forward token and add context headers for downstream services
                // WHAT: Adds Authorization header (with token) and context headers (userId, tenantId, roles)
                // HOW: Mutates request to add headers before forwarding to downstream service
                // WHY: 
                //   - Authorization header: Downstream services validate token themselves (security best practice)
                //   - X-* headers: Convenience for logging/observability (JWT is source of truth)
                // REAL-WORLD: Gateway validates → Forwards token → Catalog service validates again → 
                //            Uses X-Tenant-Id for logging → Extracts tenantId from JWT for security
                ServerHttpRequest modifiedRequest = request.mutate()
                    .header("Authorization", "Bearer " + token) // Forward token to downstream services
                    .header("X-User-Id", userId)                // Convenience header (for logging)
                    .header("X-Tenant-Id", tenantId)            // Convenience header (for logging)
                    .header("X-Roles", joinRoles(roles))       // Convenience header (for logging)
                    .build();

                // 6. Continue with modified request to downstream service
                // WHAT: Forwards request to appropriate backend service (catalog, cart, order, etc.)
                // HOW: Spring Cloud Gateway routes based on path configuration
                // WHY: Gateway is the single entry point, routes to correct microservice
                // REAL-WORLD: Request to /api/v1/catalog/products → Gateway routes to catalog service →
                //            Catalog service receives request with Authorization header → Validates token → Returns products
                return chain.filter(exchange.mutate().request(modifiedRequest).build());
            })
            .onErrorResume(IllegalArgumentException.class, error -> {
                log.warn("Token validation failed: path={}, error={}", path, error.getMessage());
                return handleUnauthorized(exchange, error.getMessage());
            });
    }

    /**
     * Extract JWT token from request (hybrid approach: Authorization header OR cookies)
     * 
     * <p><b>WHAT THIS DOES:</b>
     * Tries to extract JWT token from two sources in priority order:
     * 1. Authorization header (for mobile apps and backward compatibility)
     * 2. Cookies (for web browsers)
     * 
     * <p><b>HOW IT WORKS:</b>
     * 1. Checks Authorization header first (Bearer token format)
     * 2. If not found, checks accessToken cookie
     * 3. Returns token string or null if not found
     * 
     * <p><b>WHY WE NEED THIS:</b>
     * - <b>Hybrid Approach:</b> Supports both web (cookies) and mobile (header) clients
     * - <b>Backward Compatibility:</b> Existing clients using Authorization header continue to work
     * - <b>Priority:</b> Header takes priority (mobile apps explicitly send tokens)
     * 
     * <p><b>REAL-WORLD SCENARIOS:</b>
     * 
     * <b>Scenario 1: Mobile app request</b>
     * - App sends: Authorization: Bearer <token>
     * - Method checks header first → Finds token → Returns token
     * - Cookie check skipped (header found)
     * 
     * <b>Scenario 2: Web browser request</b>
     * - Browser sends: Cookie: accessToken=<token>
     * - Method checks header first → Not found → Checks cookies → Finds token → Returns token
     * 
     * <b>Scenario 3: Both header and cookie present</b>
     * - Request has both Authorization header and cookie
     * - Method checks header first → Finds token → Returns header token (priority)
     * - Cookie ignored (header takes precedence)
     * 
     * <b>Scenario 4: Neither present</b>
     * - Request has no Authorization header and no cookie
     * - Method checks header → Not found → Checks cookies → Not found → Returns null
     * - Filter will return 401 Unauthorized
     * 
     * @param request HTTP request (can contain Authorization header or cookies)
     * @return JWT token string, or null if not found
     */
    private String extractToken(ServerHttpRequest request) {
        // Priority 1: Try Authorization header (for mobile apps and backward compatibility)
        // WHAT: Checks for "Authorization: Bearer <token>" header
        // HOW: Reads header value and extracts token after "Bearer " prefix
        // WHY: Mobile apps explicitly send tokens in header (they don't use cookies)
        // REAL-WORLD: Mobile app → Sends token in header → Gateway reads header → Token extracted
        String authorization = request.getHeaders().getFirst("Authorization");
        if (authorization != null && authorization.startsWith("Bearer ")) {
            String token = authorization.substring(7); // Remove "Bearer " prefix
            log.debug("Token extracted from Authorization header");
            return token;
        }

        // Priority 2: Try cookies (for web browsers)
        // WHAT: Checks for "accessToken" cookie set by IAM service
        // HOW: Reads cookies from request and extracts accessToken cookie value
        // WHY: Web browsers automatically send cookies with requests (set by IAM service on login)
        // REAL-WORLD: User logs in → IAM sets cookie → Browser sends cookie → Gateway reads cookie → Token extracted
        // NOTE: Cookie name matches IAM service CookieService.ACCESS_TOKEN_COOKIE_NAME
        List<HttpCookie> cookies = request.getCookies().get(ACCESS_TOKEN_COOKIE_NAME);
        if (cookies != null && !cookies.isEmpty()) {
            String token = cookies.get(0).getValue(); // Get first cookie value (should only be one)
            log.debug("Token extracted from cookie");
            return token;
        }

        // No token found in either source
        return null;
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

