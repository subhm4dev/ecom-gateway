package com.ecom.gateway.config;

import com.ecom.jwt.config.JwtValidationProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.ArrayList;
import java.util.List;

/**
 * Gateway Configuration
 * 
 * <p>Configures public paths and maps gateway.jwt properties to jwt-validation-starter properties.
 * Note: jwt-validation-starter uses JwtValidationProperties with 'jwt' prefix,
 * so we'll use application.yml with both prefixes for backward compatibility.
 */
@Configuration
@ConfigurationProperties(prefix = "gateway")
public class GatewayConfig {

    private List<String> publicPaths = new ArrayList<>();

    /**
     * WebClient for fetching JWKS from Identity service
     * Note: This is now primarily used by jwt-validation-starter's ReactiveJwksService
     */
    @Bean
    public WebClient webClient(JwtValidationProperties jwtProperties) {
        return WebClient.builder()
            .baseUrl(jwtProperties.getIdentityServiceUrl())
            .codecs(configurer -> configurer
                .defaultCodecs()
                .maxInMemorySize(1024 * 1024)) // 1MB buffer for JWKS response
            .build();
    }

    /**
     * Get configured public paths
     */
    public List<String> getPublicPaths() {
        if (publicPaths == null || publicPaths.isEmpty()) {
            return getDefaultPublicPaths();
        }
        return publicPaths;
    }

    // Getters and setters for @ConfigurationProperties
    public void setPublicPaths(List<String> publicPaths) { 
        this.publicPaths = publicPaths != null ? publicPaths : new ArrayList<>();
    }

    /**
     * Default public paths if not configured
     * 
     * <p><b>WHAT THIS DOES:</b>
     * Defines which API endpoints are accessible without authentication.
     * These are endpoints that users need to access before they can authenticate.
     * 
     * <p><b>PUBLIC ENDPOINTS:</b>
     * - Registration: Users need to register before they can login
     * - Login: Users need to login to get tokens
     * - Refresh: Users need to refresh expired tokens (token may be expired)
     * - JWKS: Public key endpoint for token validation
     * - Health checks: Monitoring endpoints
     * - API docs: Documentation endpoints
     * 
     * <p><b>PROTECTED ENDPOINTS (NOT in this list):</b>
     * - Logout: Requires authentication (user must be logged in to logout)
     * - Logout-all: Requires authentication (user must be logged in)
     * - All other endpoints: Require valid JWT token
     * 
     * <p><b>WHY LOGOUT IS NOT PUBLIC:</b>
     * - Logout endpoint requires Authorization header (user must be authenticated)
     * - Gateway validates token before allowing logout
     * - Prevents unauthorized logout attempts
     * - Security best practice: Only authenticated users can logout
     */
    private List<String> getDefaultPublicPaths() {
        return List.of(
            "/api/v1/auth/register",      // Public: New users can register
            "/api/v1/auth/login",          // Public: Users can login (get tokens)
            "/api/v1/auth/refresh",        // Public: Users can refresh expired tokens
            "/.well-known/**",             // Public: JWKS endpoint (for token validation)
            "/actuator/**",                // Public: Health checks and monitoring
            "/swagger-ui/**",              // Public: API documentation UI
            "/v3/api-docs/**",             // Public: OpenAPI specification
            "/swagger-ui.html"             // Public: Swagger UI redirect
            // NOTE: /api/v1/auth/logout and /api/v1/auth/logout-all are NOT public
            // They require authentication - Gateway will validate token before allowing access
        );
    }
}

