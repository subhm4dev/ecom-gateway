# 🚪 E-Commerce Gateway

API Gateway service using Spring Cloud Gateway.

## Features

- Routes requests to backend microservices
- JWT validation and forwarding
- Tenant context extraction
- Error handling via custom-error-starter

## Configuration

Configuration is pulled from Config Server (`ecom-config-repo`).

Routes are configured in `ecom-config-repo/gateway/application.yml`.

## Running Locally

### Prerequisites
- Java 25
- Maven 3.9+
- Infrastructure running (Postgres, Kafka)
- Config Server running (port 8888) - optional, has fallback

### Run
```bash
mvn spring-boot:run
```

Gateway will start on port **8080**.

## Development

Add JWT validation filter and route configurations as per PRD requirements.

