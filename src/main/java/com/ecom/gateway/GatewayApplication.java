package com.ecom.gateway;

import com.ecom.gateway.config.GatewayConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Gateway Application
 *
 * <p>API Gateway service using Spring Cloud Gateway.
 * Validates JWT tokens, routes requests to backend services,
 * and forwards user context (userId, tenantId, roles).
 */
@SpringBootApplication
@EnableScheduling // Enable scheduling for JWKS cache refresh
@EnableConfigurationProperties(GatewayConfig.class) // Enable @ConfigurationProperties binding
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}

