package com.ecom.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;

/**
 * Gateway Configuration
 * 
 * <p>Configures WebClient for JWKS fetching and public paths.
 */
@Configuration
public class GatewayConfig {

    @Value("${gateway.jwt.identity-service-url:http://localhost:8081}")
    private String identityServiceUrl;

    @Value("#{'${gateway.public-paths:}'.split(',')}")
    private List<String> publicPaths;

    /**
     * WebClient for fetching JWKS from Identity service
     */
    @Bean
    public WebClient webClient() {
        return WebClient.builder()
            .baseUrl(identityServiceUrl)
            .codecs(configurer -> configurer
                .defaultCodecs()
                .maxInMemorySize(1024 * 1024)) // 1MB buffer for JWKS response
            .build();
    }

    /**
     * Get configured public paths
     */
    public List<String> getPublicPaths() {
        return publicPaths.isEmpty() ? getDefaultPublicPaths() : publicPaths;
    }

    /**
     * Default public paths if not configured
     */
    private List<String> getDefaultPublicPaths() {
        return List.of(
            "/api/auth/**",
            "/.well-known/**",
            "/actuator/**",
            "/swagger-ui/**",
            "/v3/api-docs/**",
            "/swagger-ui.html"
        );
    }
}

