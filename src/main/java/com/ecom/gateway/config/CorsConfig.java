package com.ecom.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * CORS Configuration for Gateway
 * 
 * Allows frontend applications to make cross-origin requests to the Gateway.
 * 
 * Configured to allow:
 * - Frontend apps running on localhost:3000 (Next.js dev server)
 * - All HTTP methods (GET, POST, PUT, DELETE, etc.)
 * - Authorization header (for JWT tokens)
 * - Content-Type header
 */
@Configuration
public class CorsConfig {

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        
        // Allow frontend origins
        corsConfig.setAllowedOrigins(Arrays.asList(
            "http://localhost:3000",      // Next.js dev server
            "http://localhost:3001",      // Alternative port
            "http://127.0.0.1:3000",      // Alternative localhost
            "http://127.0.0.1:3001"
        ));
        
        // Allow all HTTP methods
        corsConfig.setAllowedMethods(Arrays.asList(
            "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
        ));
        
        // Allow necessary headers
        corsConfig.setAllowedHeaders(Arrays.asList(
            "Authorization",      // For JWT tokens
            "Content-Type",        // For JSON requests
            "X-Requested-With",    // Standard header
            "X-User-Id",          // Gateway context headers
            "X-Tenant-Id",
            "X-Roles"
        ));
        
        // Allow credentials (cookies, auth headers)
        corsConfig.setAllowCredentials(true);
        
        // Cache preflight response for 1 hour
        corsConfig.setMaxAge(3600L);
        
        // Apply CORS to all paths
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);
        
        return new CorsWebFilter(source);
    }
}