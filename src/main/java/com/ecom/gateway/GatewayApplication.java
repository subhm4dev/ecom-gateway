package com.ecom.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
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
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}

