package com.ecom.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.ArrayList;
import java.util.List;

/**
 * Gateway Configuration
 * 
 * <p>Configures WebClient for JWKS fetching and public paths.
 */
@Configuration
@ConfigurationProperties(prefix = "gateway")
public class GatewayConfig {

    private JwtConfig jwt = new JwtConfig();
    private List<String> publicPaths = new ArrayList<>();

    public static class JwtConfig {
        private String identityServiceUrl = "http://localhost:8081";
        private String jwksEndpoint = "/.well-known/jwks.json";
        private long jwksCacheRefreshIntervalMs = 300000;

        // Getters and setters
        public String getIdentityServiceUrl() { return identityServiceUrl; }
        public void setIdentityServiceUrl(String identityServiceUrl) { this.identityServiceUrl = identityServiceUrl; }
        public String getJwksEndpoint() { return jwksEndpoint; }
        public void setJwksEndpoint(String jwksEndpoint) { this.jwksEndpoint = jwksEndpoint; }
        public long getJwksCacheRefreshIntervalMs() { return jwksCacheRefreshIntervalMs; }
        public void setJwksCacheRefreshIntervalMs(long jwksCacheRefreshIntervalMs) { this.jwksCacheRefreshIntervalMs = jwksCacheRefreshIntervalMs; }
    }

    /**
     * WebClient for fetching JWKS from Identity service
     */
    @Bean
    public WebClient webClient() {
        return WebClient.builder()
            .baseUrl(jwt.getIdentityServiceUrl())
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
    public JwtConfig getJwt() { return jwt; }
    public void setJwt(JwtConfig jwt) { this.jwt = jwt; }
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

