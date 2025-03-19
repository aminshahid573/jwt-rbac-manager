# JWT Role-Based Access Control Manager

## Description

`jwt-rbac-manager` is a comprehensive and flexible Node.js library for managing JSON Web Tokens (JWT) with Role-Based Access Control (RBAC). It simplifies the process of generating, verifying, refreshing, and invalidating JWTs, while also providing robust mechanisms for managing user roles and permissions. This library is designed to be highly customizable, secure, and easy to integrate into any Node.js application.

## Features

- **JWT Generation:** Generates JWT tokens with customizable expiration times, issuer, and additional claims.
- **JWT Verification:** Verifies the authenticity and validity of JWT tokens.
- **JWT Refresh:** Generates new tokens using refresh tokens, with optional rate limiting and token family support.
- **RBAC Implementation:** Manages user roles and permissions, allowing for fine-grained access control.
- **Token Invalidation:** Provides methods to invalidate individual tokens or all tokens for a user.
- **Blacklisting:** Supports token blacklisting to prevent compromised or revoked tokens from being used.
- **Customizable:** Highly configurable with options for algorithms, key management, token expiration, and more.
- **Redis Integration:** Optional integration with Redis for token blacklisting and refresh token rate limiting.
- **Middleware:** Provides Express middleware for easy integration with web applications.
- **Role Management:** Add new roles with their corresponding permissions during runtime.
- **Security:** Uses strong cryptographic algorithms and best practices to ensure token security.

## Installation

```powershell
npm install jwt-rbac-manager
```

## Usage

### Initialization

```javascript
const JWTManager = require("jwt-rbac-manager");

const jwtManager = new JWTManager({
  algorithm: "HS256", // Algorithm used for signing (HS256, RS256, etc.)
  secretKey: "your-secret-key", // Secret key for symmetric algorithms
  tokenExpiration: "1h", // Token expiration time
  refreshExpiration: "7d", // Refresh token expiration time
  issuer: "your-app", // Token issuer
  permissionsMap: {
    // Define roles and their permissions
    admin: ["read:all", "write:all", "delete:all"],
    editor: ["read:all", "write:own"],
    user: ["read:own"],
  },
  tokenBlacklist: null, // Example: Redis client
});
```
## If Using asymmetric Algorith

```javascript
const JWTManager = require("jwt-rbac-manager");

const jwtManager = new JWTManager({
  algorithm: "RS256", // Algorithm used for signing (HS256, RS256, etc.)
  privateKey: `-----BEGIN PRIVATE KEY-----
  MIIDZTCCAk2gAwIBAgIJAJtxjUkexTIXMA0GCSqGSIb3DQEBCwUAMIHnMSEwCQYD
  VQQGEwJVUzETMBEGA1UECAwCQ0ExEzARBgNVBAcMClNhbiBGcmFuY2lzY28xEjAQ
  BgNVBAoMCVBvcnRleCBMdGQxEjAQBgNVBAsMCVNvZnR3YXJlIERldjEUMBIGA1UE
  AwwLd3d3LmV4YW1wbGUxJTAjBgkqhkiG9w0BCQEWFHBvcnRleEBleGFtcGxlLmNv
  bTAeFw0yMzA5MjAyMjUyNDlaFw0yNDA5MTkyMjUyNDlaMIHnMSEwCQYDVQQGEwJV
  UzETMBEGA1UECAwCQ0ExEzARBgNVBAcMClNhbiBGcmFuY2lzY28xEjAQBgNVBAoM
  CVBvcnRleCBMdGQxEjAQBgNVBAsMCVNvZnR3YXJlIERldjEUMBIGA1UEAwwLd3d3
  LmV4YW1wbGUxJTAjBgkqhkiG9w0BCQEWFHBvcnRleEBleGFtcGxlLmNvbTCCASIw
  DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBw4jXWEYhGz1s5M5J+fUiz8n9
  jDk1u4/zLq6C3N69bT4fR2vX6qj1C6R0aB7XbL8jd0K35yN0+fP7/E3g/g3WwY1
  +4V27r9w2E3XyKxz2vhm8C6T4j0P0w5eC80uO7pP4y1sX5B6Y7h5l2r2k+v4r2E
  x+028l0a7/r3T9i/q8V9/Rk6wzXf8a6t402+Jt0N+eWc89m/G2aE/c54hXJ/m2l
  W6H7d/h2hL8fP+GfX2/3x/uJ79k/xS6R5K5/p80q2X9sJ1q74/173pU17I+G437
  9o0D4F5z9e+b8s1h422/8G9hXQIDAQABo1MwUTAdBgNVHQ4EFgQU7+VvV49p4bC
  R8SdW6q4vK3mglkwHwYDVR0jBBgwFoAU7+VvV49p4bCR8SdW6q4vK3mglkwDwYD
  VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAViX8j9B8u8qR3Q/mS8r
  N3L4H0JbW4lJ4T2jE4J260r48Qe7g355tG6t8/wA43Jq7X5uQ0U93y5/v+9zG8
  72Q6/cWv1l2Q8z9i/P5y34V5XW4h6qV2R6y4V6U+8v1m9u6K9h1vG29V4v/G9B
  4F9v38zV4N2vL8b/rF4T5P6W9p9tV8u4W6n4X6g7R7/t6G6S0W1v9c4/8H9n77
  8G6V8z5L1w1l3u38f7R9A8H9B732x/0/29P8/7+z/v7u/Q8B8F8J9X8C9B71+7
  /v76/w==
  -----END PRIVATE KEY-----`, // Private key for assymetric algo
  publicKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwHDiNdYRiEbPWzkzkj59
SLPzfYw5NbuP8y6ugtzevW0+H0dr1+qo9QukdGge12y/I3dCt+cjdPnz+/xN4P4
N1sGNfuFdu6/cNhN18isc9r4ZvAuk+I9D9MOXgvNLju6T+MtbF+QemO4eZdq9p
Pr+K9hMftNvJdGu/690/Yv6vFff0ZOsM13/GurWNNviLdDfnlmPPZvxtmhP3Oe
IVyf5tpVuh+3f4doS/Hz/hn19v98f7ie/ZP8UukeSuP6fNKtl/bCdau+P9e96
VNeyPhuN+/aNA+Bec/Xvm/LNYeNtv/BvYV0CAwEAAQ==
-----END PUBLIC KEY-----`,// public key for assymetric algo
  tokenExpiration: "1h", // Token expiration time
  refreshExpiration: "7d", // Refresh token expiration time
  issuer: "your-app", // Token issuer
  permissionsMap: {
    // Define roles and their permissions
    admin: ["read:all", "write:all", "delete:all"],
    editor: ["read:all", "write:own"],
    user: ["read:own"],
  },
  tokenBlacklist: null, // Example: Redis client
});
```

### Generating Tokens

```javascript
const userId = "user123";
const roles = ["user", "editor"];

const { token, refreshToken } = jwtManager.generateToken(userId, roles);

console.log("Token:", token);
console.log("Refresh Token:", refreshToken);
```

**Explanation:**

- `userId`: The unique identifier for the user.
- `roles`: An array of roles assigned to the user.
- `token`: The generated JWT.
- `refreshToken`: A token used to obtain a new JWT without requiring the user to re-authenticate.

### Verifying Tokens

```javascript
const token = "your-jwt-token";

jwtManager
  .verifyToken(token)
  .then((decoded) => {
    console.log("Decoded Token:", decoded);
  })
  .catch((err) => {
    console.error("Token Verification Error:", err.message);
  });
```

**Explanation:**

- `token`: The JWT to be verified.
- `decoded`: The decoded payload of the JWT, containing user information and claims.
- `err`: An error object if the token is invalid or has expired.

### Refreshing Tokens

```javascript
const refreshToken = "your-refresh-token";

jwtManager
  .refreshToken(refreshToken)
  .then(({ token, refreshToken }) => {
    console.log("New Token:", token);
    console.log("New Refresh Token:", refreshToken);
  })
  .catch((err) => {
    console.error("Token Refresh Error:", err.message);
  });
```

**Explanation:**

- `refreshToken`: The refresh token used to request a new JWT.
- `token`: The newly generated JWT.
- `refreshToken`: A new refresh token.
- `err`: An error object if the refresh token is invalid or has been revoked.

### Checking Roles

```javascript
const token = "your-jwt-token";
const requiredRoles = ["admin"];

jwtManager
  .hasRoles(token, requiredRoles)
  .then((hasRoles) => {
    console.log("Has Roles:", hasRoles); // Output: true or false
  })
  .catch((err) => {
    console.error("Error:", err.message);
  });
```

**Explanation:**

- `token`: The JWT to check.
- `requiredRoles`: An array of roles required for access.
- `hasRoles`: A boolean indicating whether the user has the required roles.

### Checking Permissions

```javascript
const token = "your-jwt-token";
const requiredPermissions = ["read:all", "write:own"];

jwtManager
  .hasPermissions(token, requiredPermissions)
  .then((hasPermissions) => {
    console.log("Has Permissions:", hasPermissions); // Output: true or false
  })
  .catch((err) => {
    console.error("Error:", err.message);
  });
```

**Explanation:**

- `token`: The JWT to check.
- `requiredPermissions`: An array of permissions required for access.
- `hasPermissions`: A boolean indicating whether the user has the required permissions.

### Invalidating Tokens

```javascript
const token = "your-jwt-token";

jwtManager
  .invalidateToken(token)
  .then((result) => {
    console.log("Token Invalidation Result:", result);
  })
  .catch((err) => {
    console.error("Token Invalidation Error:", err.message);
  });
```

**Explanation:**

- `token`: The JWT to invalidate.
- `result`: An object indicating whether the token was successfully invalidated.

### Invalidating All User Tokens

```javascript
const userId = "user123";

jwtManager
  .invalidateAllUserTokens(userId)
  .then((result) => {
    console.log("User Token Invalidation Result:", result);
  })
  .catch((err) => {
    console.error("User Token Invalidation Error:", err.message);
  });
```

**Explanation:**

- `userId`: The ID of the user whose tokens should be invalidated.
- `result`: An object indicating whether the tokens were successfully invalidated.

### Checking if a Token is Blacklisted

```javascript
const token = "your-jwt-token";

jwtManager
  .isBlacklisted(token)
  .then((isBlacklisted) => {
    console.log("Is Blacklisted:", isBlacklisted); // Output: true or false
  })
  .catch((err) => {
    console.error("Error:", err.message);
  });
```

**Explanation:**

- `token`: The JWT to check for blacklisting.
- `isBlacklisted`: A boolean indicating whether the token is blacklisted.

### Adding Roles

```javascript
jwtManager.addRole("moderator", ["read:all", "write:own", "moderate:comments"]);

// Now, the 'moderator' role is available in the permissionsMap
const userId = "user456";
const roles = ["user", "moderator"];
const { token } = jwtManager.generateToken(userId, roles);

// The generated token will include permissions from both 'user' and 'moderator' roles
```

**Explanation:**

- `role`: The name of the new role.
- `permissions`: An array of permissions associated with the new role.

### Express Middleware

```javascript
const express = require("express");
const app = express();

app.use(JWTManager.createMiddleware(jwtManager));

app.get("/protected", (req, res) => {
  res.json({ message: "Protected resource", user: req.user });
});

app.listen(3000, () => {
  console.log("Server listening on port 3000");
});
```

**Explanation:**

- The `createMiddleware` method generates an Express middleware function.
- The middleware verifies the JWT in the request header.
- If the JWT is valid, the user information is attached to the `req.user` object.
- If the JWT is invalid, an error is returned.

#### Middleware Options

```javascript
app.use(
  JWTManager.createMiddleware(jwtManager, {
    credentialsRequired: false, // Don't require JWT for all routes
    getToken: (req) => req.cookies.authToken, // Custom token extraction
    onError: (err, req, res, next) => {
      // Custom error handler
      console.error("Authentication Error:", err);
      res.status(401).json({ error: "Authentication failed" });
    },
  })
);
```

## Configuration Options

| Option                | Type    | Description                                                                  | Default Value       |
| --------------------- | ------- | ---------------------------------------------------------------------------- | ------------------- |
| `algorithm`           | String  | The algorithm used for signing the JWT (e.g., 'HS256', 'RS256').             | `'HS256'`           |
| `secretKey`           | String  | The secret key used for symmetric algorithms (e.g., 'HS256').                | `'your-secret-key'` |
| `privateKey`          | String  | The private key used for asymmetric algorithms (e.g., 'RS256').              | `null`              |
| `publicKey`           | String  | The public key used for asymmetric algorithms (e.g., 'RS256').               | `null`              |
| `tokenExpiration`     | String  | The expiration time for JWT tokens (e.g., '1h', '7d').                       | `'1h'`              |
| `refreshExpiration`   | String  | The expiration time for refresh tokens (e.g., '7d', '30d').                  | `'7d'`              |
| `issuer`              | String  | The issuer of the JWT.                                                       | `'jwt-manager'`     |
| `permissionsMap`      | Object  | An object mapping roles to their corresponding permissions.                  | `{}`                |
| `tokenBlacklist`      | Object  | An instance of a Redis client (or other store) used for token blacklisting.  | `null`              |
| `refreshTokenLimiter` | Object  | An instance of a Redis client used for rate limiting refresh token requests. | `null`              |
| `enforceIat`          | Boolean | Whether to enforce token invalidation based on the `iat` (issued at) claim.  | `false`             |

## Error Handling

The library throws custom error classes for different scenarios:

- `JWTManagerError`: Base error class.
- `TokenExpiredError`: Token has expired.
- `InvalidTokenError`: Invalid token provided.
- `TokenVerificationError`: Token verification failed.
- `TokenInvalidatedError`: Token has been invalidated.
- `RefreshTokenError`: Invalid refresh token.
- `InvalidationError`: Token invalidation failed.

You can catch these errors and handle them accordingly in your application.

## Redis Integration (Optional)

To enable token blacklisting and refresh token rate limiting, you can integrate with Redis.

1.  Install the `redis` package:

    ```powershell
    npm install redis
    ```

2.  Configure the `JWTManager` with a Redis client:

    ```javascript
    const redis = require('redis');
    const JWTManager = require('jwt-rbac-manager');

    const redisClient = redis.createClient({
        host: 'localhost',
        port: 6379
    });

    const jwtManager = new JWTManager({
        // ... other options
        tokenBlacklist: redisClient,
        refreshTokenLimiter: redisClient
    });
    ```

## Contributing

Contributions are welcome! Please feel free to submit bug reports, feature requests, or pull requests.

## License

[MIT](LICENSE)
