# Gateway Service Testing Guide

## Troubleshooting

### Lombok/Compilation Issues

If you see compilation errors about missing `log` variable, ensure Lombok annotation processing is enabled:

1. **IntelliJ IDEA**: Settings → Build, Execution, Deployment → Compiler → Annotation Processors → Enable annotation processing
2. **Maven**: Should work automatically, but if not, try:
   ```bash
   mvn clean install -DskipTests
   ```
3. **VS Code/Cursor**: Ensure Java Language Server recognizes Lombok

If issues persist, the Gateway should still run via `mvn spring-boot:run` even with IDE compilation errors.

---

## Prerequisites

Before testing, ensure these services are running:

1. **Identity Service** (port 8081)
   - Must be running to provide JWKS endpoint
   - Should have at least one active JWT key (auto-generated on startup)

2. **Redis** (port 6379)
   - Required for token blacklisting
   - Can be running via Docker: `docker compose up redis`

3. **Config Server** (port 8888) - Optional
   - Gateway has fallback configuration

## Start Services

```bash
# Terminal 1: Start Identity Service
cd ecom-iam
mvn spring-boot:run

# Terminal 2: Start Gateway
cd ecom-gateway
mvn spring-boot:run

# Terminal 3: Start Redis (if using Docker)
docker compose up redis
```

## Test Scenarios

### 1. Gateway Startup Test

**Check logs for:**
- ✅ Gateway started on port 8080
- ✅ JWKS cache initialized successfully
- ✅ Redis connection successful
- ✅ No errors on startup

**Expected:** Gateway starts without errors

---

### 2. Public Endpoints (No Authentication)

#### 2.1 Access JWKS Endpoint (via Gateway)
```bash
curl http://localhost:8080/.well-known/jwks.json
```

**Expected:** Returns JWKS JSON with public keys

#### 2.2 Access Identity Service Auth Endpoints (via Gateway)
```bash
# Register endpoint (will route to Identity service)
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123",
    "tenantId": "some-tenant-id",
    "role": "CUSTOMER"
  }'
```

**Expected:** 
- Request passes through Gateway without JWT validation
- Routes to Identity service
- Returns registration response

---

### 3. Protected Endpoints (Require Authentication)

#### 3.1 Test Without Token
```bash
curl http://localhost:8080/api/v1/profile/me
```

**Expected:** 
```json
HTTP 401 Unauthorized
{
  "error": "UNAUTHORIZED",
  "message": "Missing or invalid Authorization header"
}
```

#### 3.2 Test With Invalid Token
```bash
curl http://localhost:8080/api/v1/profile/me \
  -H "Authorization: Bearer invalid-token-here"
```

**Expected:** 
```json
HTTP 401 Unauthorized
{
  "error": "UNAUTHORIZED",
  "message": "Invalid JWT token format" (or similar)
}
```

#### 3.3 Test With Expired Token
```bash
# Use a token that has expired
curl http://localhost:8080/api/v1/profile/me \
  -H "Authorization: Bearer <expired-token>"
```

**Expected:** 
```json
HTTP 401 Unauthorized
{
  "error": "UNAUTHORIZED",
  "message": "JWT token has expired"
}
```

---

### 4. Complete Flow Test

#### 4.1 Register User
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "password123",
    "tenantId": "550e8400-e29b-41d4-a716-446655440000",
    "role": "CUSTOMER"
  }'
```

**Save the `token` from response.**

#### 4.2 Access Protected Endpoint With Valid Token
```bash
curl http://localhost:8080/api/v1/profile/me \
  -H "Authorization: Bearer <token-from-register>"
```

**Expected:**
- Request passes JWT validation
- Headers added: `X-User-Id`, `X-Tenant-Id`, `X-Roles`
- Request routes to profile service
- Profile service receives headers

#### 4.3 Test Logout (Blacklist Token)
```bash
# First, get refresh token from login/register
curl -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access-token>" \
  -d '{
    "refreshToken": "<refresh-token-from-register>"
  }'
```

**Expected:** Returns 204 No Content

#### 4.4 Test Blacklisted Token
```bash
# Use the same token from step 4.2 (now blacklisted)
curl http://localhost:8080/api/v1/profile/me \
  -H "Authorization: Bearer <blacklisted-token>"
```

**Expected:** 
```json
HTTP 401 Unauthorized
{
  "error": "UNAUTHORIZED",
  "message": "Token has been revoked"
}
```

---

### 5. JWKS Cache Test

#### 5.1 Check JWKS Cache Initialization
**Check Gateway logs:**
```
Initializing JWKS cache...
JWKS cache refreshed: 1 keys cached
```

#### 5.2 Test JWKS Refresh
Wait 5+ minutes (or trigger manually if possible), check logs for:
```
Refreshing JWKS cache from Identity service...
JWKS cache refreshed: 1 keys cached
```

---

### 6. Context Propagation Test

#### 6.1 Check Headers Forwarded
Access a protected endpoint with valid token, then check the downstream service logs (e.g., profile service) to verify it received:
- `X-User-Id` header
- `X-Tenant-Id` header
- `X-Roles` header

---

## Troubleshooting

### Gateway won't start
- Check Identity service is running (port 8081)
- Check Redis is running (port 6379)
- Check port 8080 is available

### JWKS fetch fails
- Verify Identity service is accessible at `http://localhost:8081`
- Check Identity service logs for JWKS endpoint errors
- Verify JWKS endpoint: `http://localhost:8081/.well-known/jwks.json`

### Token validation fails
- Check JWT token format (should start with `Bearer `)
- Verify token is not expired
- Check Identity service is using same key that Gateway cached

### Redis connection fails
- Verify Redis is running: `redis-cli ping` should return `PONG`
- Check Redis host/port in `application.yml`
- Redis errors are logged but don't block requests (fail open)

---

## Manual Test Checklist

- [ ] Gateway starts successfully
- [ ] JWKS endpoint accessible (public)
- [ ] Auth endpoints accessible without token (public)
- [ ] Protected endpoints reject requests without token (401)
- [ ] Protected endpoints reject invalid tokens (401)
- [ ] Protected endpoints reject expired tokens (401)
- [ ] Protected endpoints accept valid tokens (200, routes to service)
- [ ] User context headers forwarded (X-User-Id, X-Tenant-Id, X-Roles)
- [ ] Blacklisted tokens rejected (401)
- [ ] JWKS cache refreshes periodically

---

## Quick Test Script

```bash
#!/bin/bash

# 1. Test public endpoint
echo "Testing JWKS endpoint..."
curl -s http://localhost:8080/.well-known/jwks.json | jq .

# 2. Test protected endpoint without token
echo -e "\nTesting protected endpoint without token..."
curl -s -w "\nHTTP Status: %{http_code}\n" http://localhost:8080/profile/v1/profile/me

# 3. Register user and get token
echo -e "\nRegistering user..."
RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123",
    "tenantId": "550e8400-e29b-41d4-a716-446655440000",
    "role": "CUSTOMER"
  }')

TOKEN=$(echo $RESPONSE | jq -r '.token')
echo "Token received: ${TOKEN:0:50}..."

# 4. Test protected endpoint with valid token
echo -e "\nTesting protected endpoint with valid token..."
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/profile/v1/profile/me

echo -e "\nTest complete!"
```

Save as `test-gateway.sh`, make executable: `chmod +x test-gateway.sh`

