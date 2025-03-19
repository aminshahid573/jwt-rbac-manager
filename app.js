// app.js
const express = require('express');
const bodyParser = require('body-parser');
const Redis = require('ioredis');
const JWTManager = require('./index.js'); // Update path to your package
const fs = require('fs');
const path = require('path');

// Initialize Express
const app = express();
app.use(bodyParser.json());

// Setup Redis for token blacklisting and rate limiting
let redis;
try {
  redis = new Redis();
  console.log('✅ Redis connected successfully');
} catch (error) {
  console.warn('⚠️ Redis connection failed, running without blacklisting:', error.message);
}

// Initialize JWT Manager with optional asymmetric keys
const jwtManager = new JWTManager({
  // For symmetric encryption (HS256):
  secretKey: process.env.JWT_SECRET || 'your-super-secure-secret-key',
  
  // Uncomment for asymmetric encryption (RS256):
  /*
  algorithm: 'RS256',
  privateKey: fs.readFileSync(path.join(__dirname, 'keys', 'private.key')),
  publicKey: fs.readFileSync(path.join(__dirname, 'keys', 'public.key')),
  */
  
  // Token configuration
  tokenExpiration: '15m',
  refreshExpiration: '7d',
  issuer: 'jwt-test-app',
  
  // Storage for blacklisting and rate limiting
  tokenBlacklist: redis,
  refreshTokenLimiter: redis,
  enforceIat: true,
  
  // Custom permission map
  permissionsMap: {
    admin: ['users:read', 'users:write', 'users:delete', 'products:read', 'products:write', 'products:delete'],
    manager: ['users:read', 'products:read', 'products:write'],
    editor: ['products:read', 'products:write'],
    user: ['products:read']
  }
});

// Mock user database
const users = [
  { id: '1', username: 'admin', password: 'admin123', roles: ['admin'] },
  { id: '2', username: 'manager', password: 'manager123', roles: ['manager'] },
  { id: '3', username: 'editor', password: 'editor123', roles: ['editor'] },
  { id: '4', username: 'user', password: 'user123', roles: ['user'] }
];

// Track refresh tokens (in production, use Redis or a database)
const refreshTokenStore = new Map();

// =============== AUTH ROUTES ===============

// Login route
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  const user = users.find(u => u.username === username && u.password === password);
  
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Generate token with user-specific information
  const tokens = jwtManager.generateToken(user.id, user.roles, {
    additionalData: { username: user.username },
    customClaims: { app: 'jwt-test-app' }
  });
  
  // Store refresh token (in production, store in Redis/DB)
  refreshTokenStore.set(tokens.refreshToken, user.id);
  
  res.json({
    message: 'Login successful',
    user: {
      id: user.id,
      username: user.username,
      roles: user.roles
    },
    ...tokens
  });
});

// Token refresh route
app.post('/auth/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }
  
  try {
    // Check if token is in our store
    if (!refreshTokenStore.has(refreshToken)) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
    
    // Generate new token pair
    const tokens = await jwtManager.refreshToken(refreshToken);
    
    // Remove old refresh token and store new one
    refreshTokenStore.delete(refreshToken);
    refreshTokenStore.set(tokens.refreshToken, tokens.id);
    
    res.json({
      message: 'Token refreshed successfully',
      ...tokens
    });
  } catch (error) {
    if (error instanceof JWTManager.errors.RefreshTokenError) {
      return res.status(401).json({ error: error.message });
    }
    res.status(500).json({ error: 'Failed to refresh token', message: error.message });
  }
});

// Logout route
app.post('/auth/logout', async (req, res) => {
  const { token, refreshToken } = req.body;
  
  try {
    // Invalidate the access token
    if (token) {
      await jwtManager.invalidateToken(token);
    }
    
    // Remove refresh token from store
    if (refreshToken && refreshTokenStore.has(refreshToken)) {
      refreshTokenStore.delete(refreshToken);
    }
    
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Logout failed', message: error.message });
  }
});

// Logout all sessions route
app.post('/auth/logout-all', async (req, res) => {
  const authHeader = req.headers.authorization;
  
  try {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authorization header required' });
    }
    
    const token = authHeader.split(' ')[1];
    const decoded = await jwtManager.verifyToken(token);
    
    // Invalidate all tokens for this user
    await jwtManager.invalidateAllUserTokens(decoded.sub);
    
    // Clean up refresh tokens for this user
    for (const [key, userId] of refreshTokenStore.entries()) {
      if (userId === decoded.sub) {
        refreshTokenStore.delete(key);
      }
    }
    
    res.json({ message: 'All sessions logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Logout failed', message: error.message });
  }
});

// =============== MIDDLEWARE ===============

// JWT Authentication middleware
const authenticate = JWTManager.createMiddleware(jwtManager, {
  unless: req => {
    // Public routes that don't require authentication
    const publicPaths = ['/auth/login', '/auth/refresh', '/public'];
    return publicPaths.includes(req.path) || req.path.startsWith('/public/');
  }
});

// Apply the middleware to all routes
app.use(authenticate);

// =============== PROTECTED ROUTES ===============

// Public route - no auth required
app.get('/public', (req, res) => {
  res.json({ message: 'This is a public endpoint - no authentication required' });
});

// User profile - basic authentication
app.get('/profile', (req, res) => {
  res.json({
    message: 'Profile accessed successfully',
    user: req.user
  });
});

// Admin-only route
app.get('/admin', 
  JWTManager.requireRoles(['admin']), 
  (req, res) => {
    res.json({
      message: 'Admin dashboard accessed successfully',
      user: req.user
    });
  }
);

// User management - requires specific permissions
app.get('/users', 
  JWTManager.requirePermissions(['users:read']), 
  (req, res) => {
    res.json({
      message: 'User list accessed successfully',
      users: users.map(u => ({ id: u.id, username: u.username, roles: u.roles }))
    });
  }
);

// Product routes with different permission requirements
app.get('/products', 
  JWTManager.requirePermissions(['products:read']), 
  (req, res) => {
    res.json({
      message: 'Product list accessed successfully',
      products: [
        { id: 1, name: 'Product 1' },
        { id: 2, name: 'Product 2' },
        { id: 3, name: 'Product 3' }
      ]
    });
  }
);

app.post('/products', 
  JWTManager.requirePermissions(['products:write']), 
  (req, res) => {
    res.json({
      message: 'Product created successfully',
      product: { id: 4, name: req.body.name || 'New Product' }
    });
  }
);

app.delete('/products/:id', 
  JWTManager.requirePermissions(['products:delete']), 
  (req, res) => {
    res.json({
      message: `Product ${req.params.id} deleted successfully`
    });
  }
);

// Test route to check token blacklisting
app.get('/test-blacklist', (req, res) => {
  res.json({
    message: 'If you see this, your token is valid and not blacklisted',
    tokenInfo: {
      subject: req.user.sub,
      roles: req.user.roles,
      permissions: req.user.permissions,
      issuedAt: new Date(req.user.iat * 1000).toISOString(),
      expiresAt: new Date(req.user.exp * 1000).toISOString()
    }
  });
});

// =============== ERROR HANDLING ===============

app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Server error', message: err.message });
});

// =============== SERVER STARTUP ===============

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 JWT Manager test server running on port ${PORT}`);
  console.log('\n🔑 Test Users:');
  users.forEach(user => {
    console.log(`  - ${user.username} (password: ${user.password}, roles: ${user.roles.join(', ')})`);
  });
  console.log('\n📝 Test Routes:');
  console.log('  - POST /auth/login - Login with username/password');
  console.log('  - POST /auth/refresh - Refresh token');
  console.log('  - POST /auth/logout - Logout current session');
  console.log('  - POST /auth/logout-all - Logout all user sessions');
  console.log('  - GET /public - Public endpoint');
  console.log('  - GET /profile - User profile (any authenticated user)');
  console.log('  - GET /admin - Admin dashboard (admin only)');
  console.log('  - GET /users - User list (requires users:read permission)');
  console.log('  - GET /products - Product list (requires products:read permission)');
  console.log('  - POST /products - Create product (requires products:write permission)');
  console.log('  - DELETE /products/:id - Delete product (requires products:delete permission)');
  console.log('  - GET /test-blacklist - Test token blacklisting');
});

module.exports = app;
