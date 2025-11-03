# API Gateway Service Implementation Plan

## Architecture Overview

The Gateway service is the **front door** to all microservices. It:
- Validates JWT tokens from the Identity service
- Routes requests to appropriate backend services
- Extracts and forwards user context (userId, tenantId, roles)
- Handles token blacklisting for logout functionality
- Manages public vs protected endpoints

## Key Responsibilities

1. **JWT Validation**: Verify token signature, expiry, and blacklist status
2. **Routing**: Route requests to correct backend services based on path
3. **Context Propagation**: Extract user info from JWT and forward to downstream services
4. **Security**: Block invalid/expired/blacklisted tokens
5. **Public Endpoints**: Allow unauthenticated access to auth endpoints and JWKS

---

## Step-by-Step Implementation Guide

### Phase 1: Dependencies & Setup

**Step 1.1: Add Required Dependencies**
- ✅ Spring Cloud Gateway (WebFlux) - Already present
- ❌ Nimbus JOSE + JWT - For JWT validation
- ❌ Spring Data Redis (Reactive) - For token blacklisting
- ❌ WebClient - For fetching JWKS from Identity service
- ✅ Spring Cloud Config Client - Already present
- ✅ Shared libraries - Already present

**Step 1.2: Configuration**
- Routes already configured in `ecom-config-repo/gateway/application.yml`
- Add JWT validation configuration
- Add Redis connection for blacklist checks
- Add Identity service URL for JWKS fetching

---

### Phase 2: JWT Validation Service

**Step 2.1: Create JwtValidationService**
- **Package**: `com.ecom.gateway.service`
- **Purpose**: Validate JWT tokens, extract claims, check blacklist
- **Dependencies**: 
  - JWKS from Identity service
  - Redis for blacklist checks
  - Nimbus JOSE + JWT library

**Methods**:
- `validateToken(String token)` → Returns `JwtClaims` or throws exception
- `extractTokenId(String token)` → Returns JWT ID (jti) for blacklisting
- `isTokenBlacklisted(String tokenId)` → Checks Redis blacklist
- `fetchJwks()` → Fetches JWKS from Identity service (with caching)

**Key Features**:
- Cache JWKS keys (refresh periodically, e.g., every 5 minutes)
- Support multiple active keys (key rotation)
- Handle JWKS fetch failures gracefully
- Validate token signature using public keys from JWKS

---

### Phase 3: Redis Integration for Token Blacklisting

**Step 3.1: Create SessionService (Reactive)**
- **Package**: `com.ecom.gateway.service`
- **Purpose**: Check if tokens are blacklisted in Redis
- **Note**: Must use reactive Redis (ReactiveRedisTemplate) for WebFlux compatibility

**Methods**:
- `isTokenBlacklisted(String tokenId)` → Returns `Mono<Boolean>`
- Uses Redis key: `jwt:blacklist:{tokenId}`

**Why Reactive?**
- Gateway uses WebFlux (reactive), so Redis operations must be non-blocking
- Use `ReactiveRedisTemplate` instead of blocking `RedisTemplate`

---

### Phase 4: JWT Validation Filter

**Step 4.1: Create JwtAuthenticationFilter**
- **Package**: `com.ecom.gateway.filter`
- **Purpose**: Global filter to validate JWT tokens on all requests
- **Extends**: `AbstractGatewayFilterFactory` (Spring Cloud Gateway)

**Filter Logic**:
```
1. Check if path is public (auth endpoints, JWKS, actuator, swagger)
   → If public: Allow request, skip validation
   
2. Extract JWT token from Authorization header
   → If missing: Return 401 Unauthorized
   
3. Extract token ID (jti) from token
   
4. Check Redis blacklist
   → If blacklisted: Return 401 Unauthorized
   
5. Validate token (signature, expiry)
   → If invalid: Return 401 Unauthorized
   
6. Extract claims (userId, tenantId, roles)
   
7. Add headers for downstream services:
   - X-User-Id: {userId}
   - X-Tenant-Id: {tenantId}
   - X-Roles: {roles} (comma-separated)
   
8. Continue with request to backend service
```

**Public Paths** (skip validation):
- `/api/v1/auth/**` - Login, register, refresh, logout
- `/.well-known/jwks.json` - JWKS endpoint
- `/actuator/**` - Health checks, metrics
- `/swagger-ui/**`, `/v3/api-docs/**` - API documentation

---

### Phase 5: JWKS Fetcher & Cache

**Step 5.1: Create JwksService**
- **Package**: `com.ecom.gateway.service`
- **Purpose**: Fetch and cache JWKS from Identity service

**Methods**:
- `getJwks()` → Returns cached JWKS or fetches from Identity service
- `refreshJwksCache()` → Periodically refresh JWKS (every 5 minutes)
- `getPublicKey(String kid)` → Get public key by Key ID

**Caching Strategy**:
- In-memory cache (ConcurrentHashMap)
- Background refresh every 5 minutes
- Fallback: Fetch on-demand if cache miss
- Handle Identity service unavailability gracefully

**Implementation**:
- Use WebClient (reactive) to fetch from `http://localhost:8081/.well-known/jwks.json`
- Parse JWKS JSON response
- Convert to RSA public keys for Nimbus JOSE
- Cache keys by `kid` (Key ID)

---

### Phase 6: Configuration Classes

**Step 6.1: Create GatewayConfig**
- **Package**: `com.ecom.gateway.config`
- **Purpose**: Configure Gateway routes, filters, and beans

**Configuration**:
- Redis connection (reactive)
- WebClient for JWKS fetching
- JWKS cache refresh scheduler
- Public paths configuration

**Step 6.2: Create RedisConfig**
- **Package**: `com.ecom.gateway.config`
- **Purpose**: Configure reactive Redis template

**Configuration**:
- ReactiveRedisTemplate bean
- Redis connection factory
- Serialization settings

---

### Phase 7: Error Handling

**Step 7.1: Gateway Error Responses**
- Use `custom-error-starter` for consistent error format
- Handle JWT validation errors (401 Unauthorized)
- Handle routing errors (502 Bad Gateway)
- Handle timeout errors (504 Gateway Timeout)

**Error Scenarios**:
- Missing Authorization header → 401
- Invalid JWT signature → 401
- Expired token → 401
- Blacklisted token → 401
- Backend service unavailable → 502
- Backend service timeout → 504

---

### Phase 8: Testing & Validation

**Step 8.1: Integration Tests**
- Test JWT validation (valid token)
- Test JWT validation (invalid token)
- Test JWT validation (expired token)
- Test JWT validation (blacklisted token)
- Test public endpoints (no auth required)
- Test protected endpoints (auth required)
- Test context propagation (headers forwarded)

**Step 8.2: Manual Testing**
- Register user → Get token
- Access protected endpoint with token → Should work
- Access protected endpoint without token → Should fail
- Logout → Token blacklisted → Access with same token → Should fail

---

## Implementation Details

### JWT Token Format (from Identity Service)

```
Header: {
  "alg": "RS256",
  "kid": "key-1234567890"
}
Payload: {
  "sub": "user-id-uuid",
  "userId": "user-id-uuid",
  "tenantId": "tenant-id-uuid",
  "roles": ["CUSTOMER", "SELLER"],
  "jti": "jwt-id-for-blacklisting",
  "exp": 1234567890,
  "iat": 1234567890,
  "iss": "ecom-identity"
}
```

### Header Propagation

Gateway adds these headers to downstream services:
- `X-User-Id`: User UUID from JWT `sub` or `userId` claim
- `X-Tenant-Id`: Tenant UUID from JWT `tenantId` claim
- `X-Roles`: Comma-separated roles from JWT `roles` claim (e.g., "CUSTOMER,SELLER")

### Public Endpoints (No Authentication Required)

```
/api/v1/auth/register
/api/v1/auth/login
/api/v1/auth/refresh
/api/v1/auth/logout          (Note: Requires token in Identity service, but Gateway doesn't block)
/.well-known/jwks.json
/actuator/health
/actuator/info
/swagger-ui/**
/v3/api-docs/**
```

### Protected Endpoints (Authentication Required)

```
/profile/**
/address/**
/catalog/**
/inventory/**
/promo/**
/cart/**
/checkout/**
/payment/**
/order/**
```

---

## Dependencies to Add

### pom.xml Additions

```xml
<!-- JWT Validation (Nimbus JOSE + JWT) -->
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>9.37.3</version>
</dependency>

<!-- Redis Reactive (for WebFlux compatibility) -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis-reactive</artifactId>
</dependency>

<!-- WebClient for JWKS fetching -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-webflux</artifactId>
</dependency>
```

---

## Configuration Files

### application.yml (in ecom-config-repo/gateway/)

```yaml
spring:
  application:
    name: gateway
  cloud:
    gateway:
      routes:
        # Routes already configured
      
  # Redis for token blacklisting
  data:
    redis:
      host: ${REDIS_HOST:localhost}
      port: ${REDIS_PORT:6379}

# JWKS Configuration
gateway:
  jwt:
    identity-service-url: http://localhost:8081
    jwks-endpoint: /.well-known/jwks.json
    jwks-cache-refresh-interval: PT5M  # 5 minutes
  public-paths:
    - /api/v1/auth/**
    - /.well-known/**
    - /actuator/**
    - /swagger-ui/**
    - /v3/api-docs/**
```

---

## File Structure

```
ecom-gateway/
├── src/main/java/com/ecom/gateway/
│   ├── GatewayApplication.java
│   ├── config/
│   │   ├── GatewayConfig.java
│   │   ├── RedisConfig.java
│   │   └── WebClientConfig.java
│   ├── filter/
│   │   └── JwtAuthenticationFilter.java
│   ├── service/
│   │   ├── JwtValidationService.java
│   │   ├── JwksService.java
│   │   └── SessionService.java
│   └── util/
│       └── PublicPathMatcher.java
```

---

## Implementation Order

1. **Add Dependencies** → Update pom.xml
2. **Create Configuration** → Redis, WebClient, Gateway config
3. **Create JwksService** → Fetch and cache JWKS
4. **Create SessionService** → Redis blacklist checks
5. **Create JwtValidationService** → Token validation logic
6. **Create JwtAuthenticationFilter** → Gateway filter for JWT validation
7. **Wire Everything Together** → Configure filters, test
8. **Add Error Handling** → Proper error responses
9. **Testing** → Integration tests and manual validation

---

## Key Technical Decisions

### 1. Reactive vs Blocking
- **Choice**: Reactive (WebFlux)
- **Reason**: Gateway must be non-blocking for high throughput
- **Impact**: All Redis operations must use ReactiveRedisTemplate

### 2. JWKS Caching Strategy
- **Choice**: In-memory cache with periodic refresh
- **Reason**: Reduces calls to Identity service, improves performance
- **Refresh**: Every 5 minutes (configurable)

### 3. Token Blacklist Check
- **Choice**: Check Redis before validating signature
- **Reason**: Fast fail for logged-out tokens (O(1) Redis lookup)
- **Fallback**: If Redis unavailable, allow request but log warning

### 4. Public Path Matching
- **Choice**: Ant path matching with configuration
- **Reason**: Easy to add/remove public endpoints
- **Implementation**: List of patterns in config, checked before JWT validation

---

## Success Criteria

✅ Gateway validates JWT tokens correctly  
✅ Gateway blocks invalid/expired/blacklisted tokens  
✅ Gateway allows public endpoints without authentication  
✅ Gateway forwards user context (userId, tenantId, roles) to downstream services  
✅ Gateway routes requests to correct backend services  
✅ Gateway handles Identity service unavailability gracefully  
✅ Gateway caches JWKS and refreshes periodically  
✅ Gateway responds with proper error codes (401, 502, 504)

---

## Notes

- Gateway uses **reactive programming** (WebFlux), so all operations must be non-blocking
- Token blacklist check happens **before** signature validation for fast fail
- JWKS keys are cached to reduce load on Identity service
- Public endpoints list can be configured via application.yml
- Error responses follow the standard format from `custom-error-starter`

