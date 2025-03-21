# JWT Role-Based Access Control Manager

<p align="center">
  <img src="https://img.shields.io/github/license/aminshahid573/jwt-rbac-manager?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/github/stars/aminshahid573/jwt-rbac-manager?style=for-the-badge" alt="GitHub stars">
  <img src="https://img.shields.io/github/issues/aminshahid573/jwt-rbac-manager?style=for-the-badge" alt="GitHub issues">
  <img src="https://img.shields.io/npm/v/jwt-rbac-manager?style=for-the-badge" alt="NPM Version">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Made%20With%20❤️%20By-Shahid%20Amin-blue?style=for-the-badge" alt="Made With Love">
</p>


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
const fs = require('fs');
const path = require('path');

const jwtManager = new JWTManager({
  algorithm: "RS256", // Algorithm used for signing (HS256, RS256, etc.)
  privateKey: fs.readFileSync(path.join(__dirname, 'keys', 'private.key')), // Private key for assymetric algo
  publicKey: fs.readFileSync(path.join(__dirname, 'keys', 'public.key')),// public key for assymetric algo
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

## JWT-RBAC Manager: Token Blacklisting and Refresh Token Rate Limiting

This section of the README focuses on how to configure and use the token blacklisting and refresh token rate limiting features of the JWT-RBAC Manager.

### Configuration
To enable token blacklisting and refresh token rate limiting, you must configure the `tokenBlacklist` and `refreshTokenLimiter` options when initializing the `JWTManager`. This requires providing a storage adapter instance (e.g., RedisAdapter, MongoAdapter, SqlAdapter).

#### Supported Storage
1. **In-Memory (Default):** This works out of the box but is not suitable for distributed environments.
2. **Redis:** Recommended for production environments due to its performance and scalability.
3. **MongoDB/SQL:** Suitable for applications already using these databases.

```javascript
const { JWTManager, RedisAdapter } = require('jwt-rbac-manager');
const redis = require('redis');
const client = redis.createClient();

const jwtManager = new JWTManager({
    tokenBlacklist: new RedisAdapter(client),
    refreshTokenLimiter: new RedisAdapter(client)
});
```

### Token Blacklisting

#### Overview
Token blacklisting is a critical security feature that allows you to immediately invalidate JWTs, even before their natural expiration. This is essential for scenarios like user logout, account compromise, or any situation requiring immediate token revocation.

#### Implementation Details
1. **Invalidate Token:** When a user logs out or an event requires token revocation, call the `invalidateToken(token)` function. This function adds the token's JTI (JWT ID) to the blacklist with a TTL matching the token's remaining lifetime.

```javascript
app.post('/logout', async (req, res) => {
    try {
        const token = req.headers.authorization.split(' ')[1];
        await jwtManager.invalidateToken(token);
        res.status(200).send({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout failed', error);
        res.status(500).send({ error: 'Failed to logout' });
    }
});
```

2. **Global Invalidation:** For scenarios like password resets or account compromises, you may need to invalidate all tokens for a user. Use the `invalidateAllUserTokens(userId)` function. This function sets an invalidation timestamp in Redis, which is checked during token verification.

```javascript
app.post('/reset-password', async (req, res) => {
    try {
        const { userId } = req.body;
        await jwtManager.invalidateAllUserTokens(userId);
        res.status(200).send({ message: 'Password reset successful. All sessions invalidated.' });
    } catch (error) {
        console.error('Password reset failed', error);
        res.status(500).send({ error: 'Failed to reset password' });
    }
});
```

3. **Middleware Integration:** The JWTManager middleware automatically checks if a token is blacklisted before authorizing a request. If the token is blacklisted, the middleware returns a 401 Unauthorized error.
4. **Token Validation:** JWT-RBAC manager provides an dedicated validation endpoint where you can validate token is blacklist or not

```javascript
JWTManager.createValidationEndpoint = function(jwtManager) {
  return async (req, res) => {
    try {
      const token = req.query.token;
      const valid = !(await jwtManager.isBlacklisted(token));
      res.json({ valid, timestamp: Date.now() });
    } catch (error) {
      res.json({ valid: false });
    }
  };
};
```

### Refresh Token Rate Limiting

#### Overview
To prevent abuse and potential brute-force attacks, it's essential to limit the rate at which refresh tokens can be used to generate new access tokens.

#### Implementation Details

1.  **Initialization:** When creating the JWTManager instance, configure the `refreshTokenLimiter` option with a Redis adapter:
```javascript
const { JWTManager, RedisAdapter } = require('jwt-rbac-manager');
const redis = require('redis');
const client = redis.createClient();

const jwtManager = new JWTManager({
    refreshTokenLimiter: new RedisAdapter(client)
});
```

2.  **Rate Limiting Logic:**
    -The refresh token route increments a counter in redis on every try and apply expire after certain time .

```javascript
async refreshToken(refreshToken, options = {}) {
    try {
      const decoded = jwt.verify(
        refreshToken,
        this.algorithm.startsWith("HS") ? this.secretKey : this.publicKey,
        { algorithms: [this.algorithm] }
      );

      if (!decoded.isRefreshToken) {
        throw new RefreshTokenError("Invalid refresh token");
      }

      if (this.tokenBlacklist) {
        const isBlacklisted = await this.tokenBlacklist.get(
          `refresh:${decoded.jti}`
        );
        if (isBlacklisted === "true") {
          throw new RefreshTokenError("Refresh token has been revoked");
        }
      }

      if (this.refreshTokenLimiter) {
        const userId = decoded.sub;
        const key = `refresh_limit:${userId}`;
        const count = await this.refreshTokenLimiter.incr(key);

        if (count === 1) {
          await this.refreshTokenLimiter.expire(key, 3600);
        }

        if (count > 10) {
          this.auditLogger.log("REFRESH_RATE_LIMIT_EXCEEDED", { userId });
          throw new RefreshTokenError("Too many refresh attempts");
        }
      }
}
```
3.  **Error Handling:** If the rate limit is exceeded, the `refreshToken` method throws a `RefreshTokenError` with the message "Too many refresh attempts." You should handle this error in your application to provide appropriate feedback to the user.

```javascript
app.post('/refresh-token', async (req, res) => {
    try {
        const newTokenPair = await jwtManager.refreshToken(req.body.refreshToken);
        res.json(newTokenPair);
    } catch (error) {
        if (error instanceof RefreshTokenError && error.message === "Too many refresh attempts") {
            res.status(429).json({ error: 'Too many refresh attempts. Please try again later.' });
        } else {
            res.status(401).json({ error: error.message });
        }
    }
});
```

### Storage Configuration

#### In-Memory (Default)

```javascript
const { JWTManager } = require('jwt-rbac-manager');
const jwtManager = new JWTManager(); // Token blacklisting disabled
```

```javascript
const { JWTManager, MemoryAdapter } = require('jwt-rbac-manager');

const jwtManager = new JWTManager({
  tokenBlacklist: new MemoryAdapter(),
  refreshTokenLimiter: new MemoryAdapter()
});
```

##### Usage Notes
-   In-memory storage is suitable for development and testing but is **not recommended for production** due to its lack of persistence and scalability.

#### Redis

```javascript
const { JWTManager, RedisAdapter } = require('jwt-rbac-manager');
const redis = require('redis');

const redisClient = redis.createClient({
    url: 'redis://default:YOUR_REDIS_PASSWORD@localhost:6379'
});

redisClient.on('connect', () => console.log('Redis connected'));
redisClient.on('error', (error) => console.error('Redis connection error:', error));

(async () => {
    await redisClient.connect();
})();

const jwtManager = new JWTManager({
    tokenBlacklist: new RedisAdapter(redisClient),
    refreshTokenLimiter: new RedisAdapter(redisClient)
});
```

##### Configuration Notes
-   Replace `YOUR_REDIS_PASSWORD` with your actual Redis password.
-   Ensure your Redis instance is properly configured for security and performance.

#### MongoDB
```javascript
const { JWTManager, MongoAdapter } = require('jwt-rbac-manager');
const { MongoClient } = require('mongodb');

const mongoClient = new MongoClient('mongodb://user:password@localhost:27017/mydb');

const jwtManager = new JWTManager({
    tokenBlacklist: new MongoAdapter({
        collection: mongoClient.db('mydb').collection('tokenBlacklist')
    }),
    refreshTokenLimiter: new MongoAdapter({
        collection: mongoClient.db('mydb').collection('rateLimits')
    })
});
```
##### Configuration Notes
-   Replace `mongodb://user:password@localhost:27017/mydb` with your MongoDB connection string.
-   Ensure proper indexing for performance.

#### SQL
```javascript
const { JWTManager, SqlAdapter } = require('jwt-rbac-manager');
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
    host: 'localhost',
    user: 'user',
    password: 'password',
    database: 'mydb'
});

const jwtManager = new JWTManager({
    tokenBlacklist: new SqlAdapter({ db: pool, tableName: 'tokenBlacklist' }),
    refreshTokenLimiter: new SqlAdapter({ db: pool, tableName: 'rateLimits' })
});
```
##### Configuration Notes
-   Replace connection details with your SQL database credentials.
-   Ensure the SQL table is properly created as shown in the code.

### Security Best Practices

1.  **Use a Strong Redis Password:** Always set a strong password for your Redis instance to prevent unauthorized access.
2.  **Monitor Rate Limiting:** Implement monitoring to detect and respond to potential abuse or attacks.
3.  **Secure Your Storage:** Ensure your Redis, MongoDB, or SQL instances are properly secured to prevent data breaches.
4.  **Centralized Blacklist:** In a distributed system, ensure your blacklist is centralized (e.g., using Redis) so all instances can access it.

By following these guidelines, you can effectively implement token blacklisting and refresh token rate limiting to enhance the security of your JWT-based authentication system.

## Contributing

Contributions are welcome! Please feel free to submit bug reports, feature requests, or pull requests.

## License

[MIT](LICENSE)
