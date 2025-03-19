// jwt-manager/index.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Custom error classes
class JWTManagerError extends Error {
  constructor(message) {
    super(message);
    this.name = this.constructor.name;
  }
}

class TokenExpiredError extends JWTManagerError {
  constructor(message = 'Token has expired') {
    super(message);
  }
}

class InvalidTokenError extends JWTManagerError {
  constructor(message = 'Invalid token provided') {
    super(message);
  }
}

class TokenVerificationError extends JWTManagerError {
  constructor(message) {
    super(message);
  }
}

class TokenInvalidatedError extends JWTManagerError {
  constructor(message = 'Token has been invalidated') {
    super(message);
  }
}

class RefreshTokenError extends JWTManagerError {
  constructor(message = 'Invalid refresh token') {
    super(message);
  }
}

class InvalidationError extends JWTManagerError {
  constructor(message) {
    super(message);
  }
}

class JWTManager {
  constructor(options = {}) {
    // Algorithm settings
    this.algorithm = options.algorithm || 'HS256';
    
    if (this.algorithm.startsWith('HS')) {
      // Symmetric algorithms use a secret key
      this.secretKey = options.secretKey || 'your-secret-key';
      this.publicKey = this.secretKey;
    } else {
      // Asymmetric algorithms use key pairs
      this.privateKey = options.privateKey;
      this.publicKey = options.publicKey;
      
      if (!this.privateKey || !this.publicKey) {
        throw new Error(`${this.algorithm} requires both privateKey and publicKey`);
      }
    }
    
    // Token configuration
    this.tokenExpiration = options.tokenExpiration || '1h';
    this.refreshExpiration = options.refreshExpiration || '7d';
    this.issuer = options.issuer || 'jwt-manager';
    this.enforceIat = options.enforceIat || false;
    
    // Blacklisting and rate limiting
    this.tokenBlacklist = options.tokenBlacklist || null; // Redis client or other store
    this.refreshTokenLimiter = options.refreshTokenLimiter || null; // Redis client for rate limiting
    
    // RBAC configuration
    this.permissionsMap = options.permissionsMap || {
      admin: ['read:all', 'write:all', 'delete:all'],
      editor: ['read:all', 'write:own'],
      user: ['read:own']
    };
  }

  /**
   * Generate a JWT token
   * @param {String} userId - User ID
   * @param {Array} roles - Array of user roles
   * @param {Object} options - Token generation options
   * @returns {Object} - Object containing token and refresh token
   */
  generateToken(userId, roles = ['user'], options = {}) {
    if (!userId) {
      throw new InvalidTokenError('User ID is required');
    }

    const { 
      additionalData = {}, 
      customClaims = {}, 
      expiresIn = this.tokenExpiration,
      refreshExpiresIn = this.refreshExpiration
    } = options;

    // Dynamic expiration based on user role/type
    let tokenExpiration = expiresIn;
    if (!tokenExpiration) {
      if (roles.includes('admin')) {
        tokenExpiration = options.adminExpiration || this.tokenExpiration;
      } else if (roles.includes('temporary')) {
        tokenExpiration = options.temporaryExpiration || '15m';
      } else {
        tokenExpiration = this.tokenExpiration;
      }
    }

    // Standard claims
    const payload = {
      sub: userId,
      roles,
      permissions: this._derivePermissionsFromRoles(roles),
      jti: this._generateTokenId(), // Add unique token ID
      ...additionalData
    };

    // Merge custom claims (with validation)
    Object.entries(customClaims).forEach(([key, value]) => {
      // Prevent overriding protected claims
      if (!['iss', 'sub', 'iat', 'exp', 'nbf', 'jti'].includes(key)) {
        payload[key] = value;
      }
    });

    const token = jwt.sign(
      payload, 
      this.algorithm.startsWith('HS') ? this.secretKey : this.privateKey, 
      {
        expiresIn: tokenExpiration,
        issuer: this.issuer,
        algorithm: this.algorithm
      }
    );

    const refreshToken = this._generateRefreshToken(userId, roles, {
      refreshExpiresIn,
      family: options.family || this._generateTokenId()
    });

    return {
      token,
      refreshToken,
      expiresIn: this._getExpirationTime(tokenExpiration),
      refreshExpiresIn: this._getExpirationTime(refreshExpiresIn)
    };
  }

  /**
   * Verify a JWT token
   * @param {String} token - JWT token to verify
   * @returns {Object} - Decoded token payload
   */
  async verifyToken(token) {
    try {
      const decoded = jwt.verify(
        token, 
        this.publicKey, 
        { algorithms: [this.algorithm] }
      );
      
      // Check if token is blacklisted based on timestamp
      if (this.enforceIat && this.tokenBlacklist) {
        const invalidationTime = await this.tokenBlacklist.get(`user:${decoded.sub}:invalidation_time`);
        if (invalidationTime && decoded.iat < parseInt(invalidationTime)) {
          throw new TokenInvalidatedError('Token has been invalidated');
        }
      }
      
      // Check if token is directly blacklisted
      if (this.tokenBlacklist) {
        const tokenId = decoded.jti || decoded.sub;
        const isBlacklisted = await this.tokenBlacklist.get(`blacklist:${tokenId}`);
        if (isBlacklisted === 'true') {
          throw new TokenInvalidatedError('Token has been invalidated');
        }
      }
      
      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new TokenExpiredError('Token has expired');
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new InvalidTokenError(error.message || 'Invalid token provided');
      } else if (error instanceof TokenInvalidatedError) {
        throw error;
      } else {
        throw new TokenVerificationError(`Token verification failed: ${error.message}`);
      }
    }
  }

  /**
   * Generate a new token using refresh token
   * @param {String} refreshToken - Refresh token
   * @param {Object} options - Options for new token
   * @returns {Object} - New token pair
   */
  async refreshToken(refreshToken, options = {}) {
    try {
      const decoded = jwt.verify(
        refreshToken, 
        this.algorithm.startsWith('HS') ? this.secretKey : this.publicKey,
        { algorithms: [this.algorithm] }
      );
      
      // Check if this is actually a refresh token
      if (!decoded.isRefreshToken) {
        throw new RefreshTokenError('Invalid refresh token');
      }
      
      // Check if refresh token is blacklisted
      if (this.tokenBlacklist) {
        const isBlacklisted = await this.tokenBlacklist.get(`refresh:${decoded.jti}`);
        if (isBlacklisted === 'true') {
          throw new RefreshTokenError('Refresh token has been revoked');
        }
      }
      
      // Apply rate limiting if configured
      if (this.refreshTokenLimiter) {
        const userId = decoded.sub;
        const key = `refresh_limit:${userId}`;
        
        // Increment counter and get current value
        const count = await this.refreshTokenLimiter.incr(key);
        
        // Set expiry for the counter if it's new
        if (count === 1) {
          await this.refreshTokenLimiter.expire(key, 3600); // 1 hour window
        }
        
        // Check if limit is reached (e.g., 10 refreshes per hour)
        if (count > 10) {
          throw new RefreshTokenError('Too many refresh attempts');
        }
      }

      // Generate new tokens with family continuity for refresh token chaining
      const tokenPair = this.generateToken(decoded.sub, decoded.roles, {
        additionalData: { previousIat: decoded.iat },
        family: decoded.family, // Maintain the family for refresh token chaining
        ...options
      });
      
      // Blacklist the used refresh token
      if (this.tokenBlacklist) {
        const remainingTtl = decoded.exp - Math.floor(Date.now() / 1000);
        if (remainingTtl > 0) {
          await this.tokenBlacklist.set(`refresh:${decoded.jti}`, 'true', 'EX', remainingTtl);
        }
      }
      
      return tokenPair;
    } catch (error) {
      if (error instanceof RefreshTokenError) {
        throw error;
      } else if (error instanceof jwt.TokenExpiredError) {
        throw new RefreshTokenError('Refresh token has expired');
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new RefreshTokenError(`Invalid refresh token: ${error.message}`);
      }
      throw new RefreshTokenError(`Token refresh failed: ${error.message}`);
    }
  }

  /**
   * Check if user has required roles
   * @param {String} token - JWT token
   * @param {Array} requiredRoles - Roles required for access
   * @returns {Boolean} - Whether user has required roles
   */
  async hasRoles(token, requiredRoles = []) {
    const decoded = await this.verifyToken(token);
    
    if (!decoded.roles || !Array.isArray(decoded.roles)) {
      return false;
    }

    return requiredRoles.every(role => decoded.roles.includes(role));
  }

  /**
   * Check if user has required permissions
   * @param {String} token - JWT token
   * @param {Array} requiredPermissions - Permissions required for access
   * @returns {Boolean} - Whether user has required permissions
   */
  async hasPermissions(token, requiredPermissions = []) {
    const decoded = await this.verifyToken(token);
    
    if (!decoded.permissions || !Array.isArray(decoded.permissions)) {
      return false;
    }

    return requiredPermissions.every(permission => 
      decoded.permissions.includes(permission)
    );
  }

  /**
   * Invalidate a token (for logout)
   * @param {String} token - Token to invalidate
   * @returns {Object} - Result of invalidation
   */
  async invalidateToken(token) {
    try {
      const decoded = await this.verifyToken(token);
      const tokenId = decoded.jti || decoded.sub;
      const expiryTime = decoded.exp - Math.floor(Date.now() / 1000);
      
      if (this.tokenBlacklist) {
        // Store in blacklist until token expiry
        if (expiryTime > 0) {
          await this.tokenBlacklist.set(`blacklist:${tokenId}`, 'true', 'EX', expiryTime);
        }
      }
      
      return {
        invalidated: true,
        expiresAt: new Date(decoded.exp * 1000)
      };
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        // No need to blacklist an expired token
        return { invalidated: true, expired: true };
      }
      throw new InvalidationError(`Failed to invalidate token: ${error.message}`);
    }
  }

  /**
   * Invalidate all tokens for a user
   * @param {String} userId - User ID
   * @returns {Object} - Result of invalidation
   */
  async invalidateAllUserTokens(userId) {
    try {
      if (!this.tokenBlacklist) {
        throw new InvalidationError('Token blacklist store is not configured');
      }
      
      const invalidationTime = Math.floor(Date.now() / 1000);
      await this.tokenBlacklist.set(`user:${userId}:invalidation_time`, invalidationTime);
      
      return {
        invalidated: true,
        timestamp: invalidationTime
      };
    } catch (error) {
      throw new InvalidationError(`Failed to invalidate user tokens: ${error.message}`);
    }
  }

  /**
   * Check if a token is blacklisted
   * @param {String} token - Token to check
   * @returns {Boolean} - Whether the token is blacklisted
   */
  async isBlacklisted(token) {
    try {
      const decoded = jwt.verify(
        token, 
        this.algorithm.startsWith('HS') ? this.secretKey : this.publicKey,
        { algorithms: [this.algorithm] }
      );
      
      const tokenId = decoded.jti || decoded.sub;
      
      if (!this.tokenBlacklist) return false;
      
      // Check direct blacklisting
      const result = await this.tokenBlacklist.get(`blacklist:${tokenId}`);
      if (result === 'true') return true;
      
      // Check timestamp-based invalidation if enforced
      if (this.enforceIat) {
        const invalidationTime = await this.tokenBlacklist.get(`user:${decoded.sub}:invalidation_time`);
        if (invalidationTime && decoded.iat < parseInt(invalidationTime)) {
          return true;
        }
      }
      
      return false;
    } catch (error) {
      return false; // Invalid tokens shouldn't be considered blacklisted
    }
  }

  /**
   * Allow adding new roles at runtime
   * @param {String} role - Role name
   * @param {Array} permissions - Array of permissions for the role
   */
  addRole(role, permissions) {
    this.permissionsMap[role] = permissions;
  }

  /**
   * Generate a refresh token
   * @param {String} userId - User ID
   * @param {Array} roles - User roles
   * @param {Object} options - Options for refresh token
   * @returns {String} - Refresh token
   * @private
   */
  _generateRefreshToken(userId, roles = ['user'], options = {}) {
    const refreshPayload = { 
      sub: userId,
      roles,
      isRefreshToken: true,
      jti: this._generateTokenId() // Add unique ID for blacklisting
    };
    
    // Add family ID to track refresh token chains for better security
    if (options.family) {
      refreshPayload.family = options.family;
    }

    return jwt.sign(
      refreshPayload,
      this.algorithm.startsWith('HS') ? this.secretKey : this.privateKey,
      {
        expiresIn: options.refreshExpiresIn || this.refreshExpiration,
        issuer: this.issuer,
        algorithm: this.algorithm
      }
    );
  }

  /**
   * Calculate expiration time in seconds
   * @param {String} expirationString - Expiration time (e.g., '1h', '7d')
   * @returns {Number} - Expiration time in seconds
   * @private
   */
  _getExpirationTime(expirationString) {
    const timeUnits = {
      s: 1,
      m: 60,
      h: 60 * 60,
      d: 24 * 60 * 60
    };

    const match = expirationString.match(/^(\d+)([smhd])$/);
    if (!match) {
      return 3600; // Default to 1 hour
    }

    const [, time, unit] = match;
    return parseInt(time) * timeUnits[unit];
  }

  /**
   * Derive permissions from roles
   * @param {Array} roles - User roles
   * @returns {Array} - Derived permissions
   * @private
   */
  _derivePermissionsFromRoles(roles) {
    const permissions = new Set();
    
    roles.forEach(role => {
      if (this.permissionsMap[role]) {
        this.permissionsMap[role].forEach(permission => {
          permissions.add(permission);
        });
      }
    });

    return Array.from(permissions);
  }

  /**
   * Generate a unique token ID
   * @returns {String} - Unique token ID
   * @private
   */
  _generateTokenId() {
    return crypto.randomBytes(16).toString('hex');
  }
}

// Express middleware
JWTManager.createMiddleware = function(jwtManager, options = {}) {
  const { 
    credentialsRequired = true,
    getToken = req => {
      if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        return req.headers.authorization.split(' ')[1];
      }
      return null;
    },
    onError = (err, req, res, next) => {
      if (err instanceof TokenExpiredError) {
        return res.status(401).json({ error: 'Token expired' });
      } else if (err instanceof TokenInvalidatedError) {
        return res.status(401).json({ error: 'Token revoked' });
      } else if (err instanceof InvalidTokenError) {
        return res.status(401).json({ error: 'Invalid token' });
      }
      return res.status(401).json({ error: 'Authentication failed' });
    },
    unless = () => false
  } = options;

  return async function(req, res, next) {
    try {
      // Skip middleware if unless function returns true
      if (unless(req)) {
        return next();
      }

      const token = getToken(req);
      
      if (!token) {
        if (credentialsRequired) {
          throw new InvalidTokenError('No token provided');
        } else {
          return next();
        }
      }
      
      // Verify token and add to request
      const decoded = await jwtManager.verifyToken(token);
      req.user = decoded;
      next();
    } catch (error) {
      return onError(error, req, res, next);
    }
  };
};

// RBAC middleware helpers
JWTManager.requireRoles = function(requiredRoles = []) {
  return (req, res, next) => {
    if (!req.user || !req.user.roles) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const hasAllRoles = requiredRoles.every(role => req.user.roles.includes(role));
    
    if (hasAllRoles) {
      return next();
    }
    
    return res.status(403).json({ error: 'Insufficient roles' });
  };
};

JWTManager.requirePermissions = function(requiredPermissions = []) {
  return (req, res, next) => {
    if (!req.user || !req.user.permissions) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const hasAllPermissions = requiredPermissions.every(
      permission => req.user.permissions.includes(permission)
    );
    
    if (hasAllPermissions) {
      return next();
    }
    
    return res.status(403).json({ error: 'Insufficient permissions' });
  };
};

// Export error classes for external use
JWTManager.errors = {
  JWTManagerError,
  TokenExpiredError,
  InvalidTokenError,
  TokenVerificationError,
  TokenInvalidatedError,
  RefreshTokenError,
  InvalidationError
};

module.exports = JWTManager;
