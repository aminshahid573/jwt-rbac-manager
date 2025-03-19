# JWT Role-Based Access Control Manager

A comprehensive JWT (JSON Web Token) management solution with support for token blacklisting, refresh tokens, RBAC (Role-Based Access Control), and Express middleware integration.

## Features

- 🔐 Support for both symmetric (HS*) and asymmetric (RS*, ES*) algorithms
- 🔄 Refresh token rotation with family-based tracking
- ⚡ Express middleware integration
- 🚫 Token blacklisting support
- 🔑 Role-Based Access Control (RBAC)
- ⏱️ Rate limiting for refresh tokens
- 🛡️ Protection against token reuse
- 🎯 Custom error handling

## Installation

```bash
npm install jwt-rbac-manager
# or
yarn add jwt-rbac-manager
```

## Basic Usage

### Initialize the Manager

```javascript
const JWTManager = require('jwt-rbac-manager');

// Basic initialization with symmetric algorithm (HS256)
const jwtManager = new JWTManager({
  secretKey: 'your-secure-secret-key'
});

// Or with asymmetric algorithm (RS256)
const jwtManager = new JWTManager({
  algorithm: 'RS256',
  privateKey: fs.readFileSync('private.key'),
  publicKey: fs.readFileSync('public.key')
});
```

### Generate Tokens

```javascript
// Generate a token pair (access token + refresh token)
const { token, refreshToken } = await jwtManager.generateToken(
  'user123',
  ['user'],
  {
    additionalData: { email: 'user@example.com' },
    customClaims: { organization: 'acme' }
  }
);
```

### Verify Tokens

```javascript
try {
  const decoded = await jwtManager.verifyToken(token);
  console.log(decoded); // { sub: 'user123', roles: ['user'], ... }
} catch (error) {
  if (error instanceof JWTManager.errors.TokenExpiredError) {
    console.log('Token has expired');
  }
}
```

### Refresh Tokens

```javascript
try {
  const { token: newToken, refreshToken: newRefreshToken } = 
    await jwtManager.refreshToken(refreshToken);
} catch (error) {
  if (error instanceof JWTManager.errors.RefreshTokenError) {
    console.log('Invalid refresh token');
  }
}
```

## Express Middleware Integration

### Basic Authentication Middleware

```javascript
const express = require('express');
const app = express();

// Create middleware
const jwtMiddleware = JWTManager.createMiddleware(jwtManager);

// Apply middleware to protected routes
app.use('/api', jwtMiddleware);

// Protected route
app.get('/api/profile', (req, res) => {
  // req.user contains the decoded token
  res.json({ user: req.user });
});
```

### Role-Based Authorization

```javascript
app.get('/api/admin',
  jwtMiddleware,
  JWTManager.requireRoles(['admin']),
  (req, res) => {
    res.json({ message: 'Admin access granted' });
  }
);

app.get('/api/content',
  jwtMiddleware,
  JWTManager.requirePermissions(['read:content']),
  (req, res) => {
    res.json({ message: 'Content access granted' });
  }
);
```

## Advanced Configuration

### With Redis Blacklisting

```javascript
const Redis = require('ioredis');
const redis = new Redis();

const jwtManager = new JWTManager({
  secretKey: 'your-secure-secret-key',
  tokenBlacklist: redis,
  refreshTokenLimiter: redis,
  enforceIat: true
});

// Invalidate a token (logout)
await jwtManager.invalidateToken(token);

// Invalidate all user tokens
await jwtManager.invalidateAllUserTokens('user123');
```

### Custom Role Permissions

```javascript
const jwtManager = new JWTManager({
  secretKey: 'your-secure-secret-key',
  permissionsMap: {
    admin: ['read:all', 'write:all', 'delete:all'],
    editor: ['read:all', 'write:own'],
    user: ['read:own']
  }
});

// Add new roles at runtime
jwtManager.addRole('moderator', ['read:all', 'moderate:content']);
```

### Custom Middleware Options

```javascript
const middleware = JWTManager.createMiddleware(jwtManager, {
  credentialsRequired: false,
  getToken: (req) => req.query.token,
  onError: (err, req, res, next) => {
    res.status(401).json({ message: 'Custom error handling' });
  },
  unless: (req) => req.path === '/public'
});
```

## Error Handling

The package provides several custom error classes:

```javascript
const {
  JWTManagerError,
  TokenExpiredError,
  InvalidTokenError,
  TokenVerificationError,
  TokenInvalidatedError,
  RefreshTokenError,
  InvalidationError
} = JWTManager.errors;

try {
  await jwtManager.verifyToken(token);
} catch (error) {
  if (error instanceof TokenExpiredError) {
    // Handle expired token
  } else if (error instanceof InvalidTokenError) {
    // Handle invalid token
  }
}
```

## API Reference

### JWTManager Class

#### Constructor Options
- `algorithm`: Token signing algorithm (default: 'HS256')
- `secretKey`: Secret key for symmetric algorithms
- `privateKey`: Private key for asymmetric algorithms
- `publicKey`: Public key for asymmetric algorithms
- `tokenExpiration`: Access token expiration (default: '1h')
- `refreshExpiration`: Refresh token expiration (default: '7d')
- `issuer`: Token issuer (default: 'jwt-rbac-manager')
- `enforceIat`: Enable timestamp-based invalidation (default: false)
- `tokenBlacklist`: Redis client for token blacklisting
- `refreshTokenLimiter`: Redis client for refresh token rate limiting
- `permissionsMap`: RBAC permissions configuration

#### Methods
- `generateToken(userId, roles, options)`
- `verifyToken(token)`
- `refreshToken(refreshToken, options)`
- `hasRoles(token, requiredRoles)`
- `hasPermissions(token, requiredPermissions)`
- `invalidateToken(token)`
- `invalidateAllUserTokens(userId)`
- `isBlacklisted(token)`
- `addRole(role, permissions)`

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
