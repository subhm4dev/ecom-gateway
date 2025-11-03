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
     */
    private List<String> getDefaultPublicPaths() {
        return List.of(
            "/api/v1/auth/**",
            "/.well-known/**",
            "/actuator/**",
            "/swagger-ui/**",
            "/v3/api-docs/**",
            "/swagger-ui.html"
        );
    }
}

