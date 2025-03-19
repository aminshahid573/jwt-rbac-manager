// jwt-manager/index.js
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

// Custom error classes
class JWTManagerError extends Error {
  constructor(message, code = "JWT_ERROR") {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
  }
}

class TokenExpiredError extends JWTManagerError {
  constructor(message = "Token has expired") {
    super(message);
  }
}

class InvalidTokenError extends JWTManagerError {
  constructor(message = "Invalid token provided") {
    super(message);
  }
}

class TokenVerificationError extends JWTManagerError {
  constructor(message) {
    super(message);
  }
}

class TokenInvalidatedError extends JWTManagerError {
  constructor(message = "Token has been invalidated") {
    super(message);
  }
}

class RefreshTokenError extends JWTManagerError {
  constructor(message = "Invalid refresh token") {
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
    this.algorithm = options.algorithm || "HS256";

    if (this.algorithm.startsWith("HS")) {
      // Symmetric algorithms use a secret key
      this.secretKey = options.secretKey || "your-secret-key";
      this.publicKey = this.secretKey;
    } else {
      // Asymmetric algorithms use key pairs
      this.privateKey = options.privateKey;
      this.publicKey = options.publicKey;

      if (!this.privateKey || !this.publicKey) {
        throw new Error(
          `${this.algorithm} requires both privateKey and publicKey`
        );
      }
    }

    // Token configuration
    this.tokenExpiration = options.tokenExpiration || "1h";
    this.refreshExpiration = options.refreshExpiration || "7d";
    this.issuer = options.issuer || "jwt-manager";
    this.enforceIat = options.enforceIat || false;

    // Blacklisting and rate limiting
    this.tokenBlacklist = options.tokenBlacklist || null; // Redis client or other store
    this.refreshTokenLimiter = options.refreshTokenLimiter || null; // Redis client for rate limiting

    // RBAC configuration
    this.permissionsMap = options.permissionsMap || {
      admin: ["read:all", "write:all", "delete:all"],
      editor: ["read:all", "write:own"],
      user: ["read:own"],
    };
    // New features configuration
    this.auditLogger = options.auditLogger || {
      log: (eventType, data) => console.log(`[AUDIT] ${eventType}:`, data),
    };

    this.mfaProvider = options.mfaProvider || null;
    this.rateLimitProfiles = options.rateLimitProfiles || {
      sensitive: { requests: 5, window: "1m" },
      normal: { requests: 50, window: "5m" },
    };

    this.sessionConfig = options.sessionConfig || {
      maxSessions: 5,
      sessionExpiry: "30d",
    };

    // Token version tracking
    this.tokenVersions = new Map();
  }

  /**
   * Generate a JWT token
   * @param {String} userId - User ID
   * @param {Array} roles - Array of user roles
   * @param {Object} options - Token generation options
   * @returns {Object} - Object containing token and refresh token
   */
  generateToken(userId, roles = ["user"], options = {}) {
    if (!userId) {
      throw new InvalidTokenError("User ID is required");
    }

    const {
      additionalData = {},
      customClaims = {},
      expiresIn = this.tokenExpiration,
      refreshExpiresIn = this.refreshExpiration,
    } = options;

    // Dynamic expiration based on user role/type
    let tokenExpiration = expiresIn;
    if (!tokenExpiration) {
      if (roles.includes("admin")) {
        tokenExpiration = options.adminExpiration || this.tokenExpiration;
      } else if (roles.includes("temporary")) {
        tokenExpiration = options.temporaryExpiration || "15m";
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
      ...additionalData,
    };

    // Merge custom claims (with validation)
    Object.entries(customClaims).forEach(([key, value]) => {
      // Prevent overriding protected claims
      if (!["iss", "sub", "iat", "exp", "nbf", "jti"].includes(key)) {
        payload[key] = value;
      }
    });

    const token = jwt.sign(
      payload,
      this.algorithm.startsWith("HS") ? this.secretKey : this.privateKey,
      {
        expiresIn: tokenExpiration,
        issuer: this.issuer,
        algorithm: this.algorithm,
      }
    );

    const refreshToken = this._generateRefreshToken(userId, roles, {
      refreshExpiresIn,
      family: options.family || this._generateTokenId(),
    });

    return {
      token,
      refreshToken,
      expiresIn: this._getExpirationTime(tokenExpiration),
      refreshExpiresIn: this._getExpirationTime(refreshExpiresIn),
    };
  }

  /**
   * Verify a JWT token
   * @param {String} token - JWT token to verify
   * @returns {Object} - Decoded token payload
   */
  async verifyToken(token, mfaOptions = {}) {
    try {
      const decoded = jwt.verify(token, this.publicKey, {
        algorithms: [this.algorithm],
      });

      // Check if token is blacklisted based on timestamp
      if (this.enforceIat && this.tokenBlacklist) {
        const invalidationTime = await this.tokenBlacklist.get(
          `user:${decoded.sub}:invalidation_time`
        );
        if (invalidationTime && decoded.iat < parseInt(invalidationTime)) {
          throw new TokenInvalidatedError("Token has been invalidated");
        }
      }

      // Check if token is directly blacklisted
      if (this.tokenBlacklist) {
        const tokenId = decoded.jti || decoded.sub;
        const isBlacklisted = await this.tokenBlacklist.get(
          `blacklist:${tokenId}`
        );
        if (isBlacklisted === "true") {
          throw new TokenInvalidatedError("Token has been invalidated");
        }
      }

      // MFA verification
      if (decoded.mfaRequired && this.mfaProvider) {
        if (!mfaOptions.code) {
          throw new JWTManagerError("MFA required", "MFA_REQUIRED");
        }

        const valid = await this.mfaProvider.verify(decoded.sub, mfaOptions.code);
        if (!valid) {
          this.auditLogger.log("MFA_FAILURE", { userId: decoded.sub });
          throw new JWTManagerError("MFA verification failed", "MFA_FAILED");
        }
      }

      // Validate token version if available
      if (decoded.tv) {
        const versionValid = await this.validateTokenVersion(decoded);
        if (!versionValid) {
          throw new TokenInvalidatedError("Token version outdated");
        }
      }

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new TokenExpiredError("Token has expired");
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new InvalidTokenError(error.message || "Invalid token provided");
      } else if (error instanceof TokenInvalidatedError) {
        throw error;
      } else if (error instanceof JWTManagerError) {
        throw error;
      } else {
        throw new TokenVerificationError(
          `Token verification failed: ${error.message}`
        );
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
        this.algorithm.startsWith("HS") ? this.secretKey : this.publicKey,
        { algorithms: [this.algorithm] }
      );

      // Check if this is actually a refresh token
      if (!decoded.isRefreshToken) {
        throw new RefreshTokenError("Invalid refresh token");
      }

      // Check if refresh token is blacklisted
      if (this.tokenBlacklist) {
        const isBlacklisted = await this.tokenBlacklist.get(
          `refresh:${decoded.jti}`
        );
        if (isBlacklisted === "true") {
          throw new RefreshTokenError("Refresh token has been revoked");
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
          throw new RefreshTokenError("Too many refresh attempts");
        }
      }

      // Generate new tokens with family continuity for refresh token chaining
      const tokenPair = this.generateToken(decoded.sub, decoded.roles, {
        additionalData: { previousIat: decoded.iat },
        family: decoded.family, // Maintain the family for refresh token chaining
        ...options,
      });

      // Blacklist the used refresh token
      if (this.tokenBlacklist) {
        const remainingTtl = decoded.exp - Math.floor(Date.now() / 1000);
        if (remainingTtl > 0) {
          await this.tokenBlacklist.set(
            `refresh:${decoded.jti}`,
            "true",
            "EX",
            remainingTtl
          );
        }
      }

      return tokenPair;
    } catch (error) {
      if (error instanceof RefreshTokenError) {
        throw error;
      } else if (error instanceof jwt.TokenExpiredError) {
        throw new RefreshTokenError("Refresh token has expired");
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

    return requiredRoles.every((role) => decoded.roles.includes(role));
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

    return requiredPermissions.every((permission) =>
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
          await this.tokenBlacklist.set(
            `blacklist:${tokenId}`,
            "true",
            "EX",
            expiryTime
          );
        }
      }

      return {
        invalidated: true,
        expiresAt: new Date(decoded.exp * 1000),
      };
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        // No need to blacklist an expired token
        return { invalidated: true, expired: true };
      }
      throw new InvalidationError(
        `Failed to invalidate token: ${error.message}`
      );
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
        throw new InvalidationError("Token blacklist store is not configured");
      }

      const invalidationTime = Math.floor(Date.now() / 1000);
      await this.tokenBlacklist.set(
        `user:${userId}:invalidation_time`,
        invalidationTime
      );

      return {
        invalidated: true,
        timestamp: invalidationTime,
      };
    } catch (error) {
      throw new InvalidationError(
        `Failed to invalidate user tokens: ${error.message}`
      );
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
        this.algorithm.startsWith("HS") ? this.secretKey : this.publicKey,
        { algorithms: [this.algorithm] }
      );

      if (!this.tokenBlacklist) return false;

      // Check timestamp-based invalidation
      if (this.enforceIat) {
        const invalidationTime = await this.tokenBlacklist.get(
          `user:${decoded.sub}:invalidation_time`
        );
        
        // The mock is returning the invalidation time directly
        // We need to handle both cases: when it's a direct response and when it's from Redis
        const parsedTime = parseInt(invalidationTime, 10);
        if (!isNaN(parsedTime) && decoded.iat <= parsedTime) {
          return true;
        }
      }

      // Check direct blacklisting
      const tokenId = decoded.jti || decoded.sub;
      const result = await this.tokenBlacklist.get(`blacklist:${tokenId}`);
      return result === "true";

    } catch (error) {
      return false;
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
  _generateRefreshToken(userId, roles = ["user"], options = {}) {
    const refreshPayload = {
      sub: userId,
      roles,
      isRefreshToken: true,
      jti: this._generateTokenId(), // Add unique ID for blacklisting
    };

    // Add family ID to track refresh token chains for better security
    if (options.family) {
      refreshPayload.family = options.family;
    }

    return jwt.sign(
      refreshPayload,
      this.algorithm.startsWith("HS") ? this.secretKey : this.privateKey,
      {
        expiresIn: options.refreshExpiresIn || this.refreshExpiration,
        issuer: this.issuer,
        algorithm: this.algorithm,
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
      d: 24 * 60 * 60,
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

    roles.forEach((role) => {
      if (this.permissionsMap[role]) {
        this.permissionsMap[role].forEach((permission) => {
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
    return crypto.randomBytes(16).toString("hex");
  }

  /** NEW FEATURE: Dynamic Role Updates with Versioning */
  async updateRole(role, newPermissions) {
    if (!this.permissionsMap[role]) {
      throw new JWTManagerError(`Role ${role} not found`, "ROLE_NOT_FOUND");
    }

    this.permissionsMap[role] = newPermissions;
    const newVersion = Date.now();
    this.tokenVersions.set(role, newVersion);

    this.auditLogger.log("ROLE_UPDATED", {
      role,
      newPermissions,
      version: newVersion,
    });

    return { role, version: newVersion };
  }

  /** NEW FEATURE: Token Version Validation */
  async validateTokenVersion(decodedToken) {
    const roleVersions = await Promise.all(
      decodedToken.roles.map(async (role) => ({
        role,
        currentVersion: this.tokenVersions.get(role) || 0,
        tokenVersion: decodedToken.tv[role] || 0,
      }))
    );

    return roleVersions.every((v) => v.currentVersion <= v.tokenVersion);
  }

  /** NEW FEATURE: Session Management */
  async trackSession(userId, tokenData) {
    const sessions = await this.getSessions(userId);
    if (sessions.length >= this.sessionConfig.maxSessions) {
      await this.invalidateOldestSession(userId);
    }

    const sessionId = this._generateTokenId();
    const sessionData = {
      jti: tokenData.jti,
      issuedAt: new Date(),
      device: tokenData.device,
      lastAccessed: Date.now(),
    };

    await this.tokenBlacklist.hSet(
      `sessions:${userId}`,
      sessionId,
      JSON.stringify(sessionData)
    );

    return sessionId;
  }

  async getSessions(userId) {
    const sessions = await this.tokenBlacklist.hGetAll(`sessions:${userId}`);
    return Object.entries(sessions).map(([id, data]) => ({
      id,
      ...JSON.parse(data),
    }));
  }

  /** NEW FEATURE: Risk-based Authentication */
  async analyzeTokenRisk(token) {
    const decoded = await this.verifyToken(token);
    const usagePatterns = await this.getUsagePatterns(decoded.sub);

    return {
      riskScore: this._calculateRiskScore(usagePatterns),
      lastLocation: decoded.geo || "Unknown",
      deviceMatch: this._checkDeviceConsistency(decoded),
      unusualActivity: this._detectAnomalies(usagePatterns),
    };
  }

  /** NEW FEATURE: Token Compression */
  generateCompressedToken(userId, roles, options = {}) {
    const payload = this._createCompactPayload(userId, roles, options);
    return jwt.sign(payload, this.secretKey, {
      algorithm: "HS256",
      expiresIn: options.expiresIn,
    });
  }

  _createCompactPayload(userId, roles) {
    return {
      sub: userId,
      r: roles.join(","),
      p: this._derivePermissionsFromRoles(roles).join("|"),
      v: this._getRoleVersions(roles),
      c: Math.floor(Date.now() / 1000),
    };
  }
}

// Express middleware
// Express middleware with security headers and enhanced error handling
JWTManager.createMiddleware = function(jwtManager, options = {}) {
  const { 
    credentialsRequired = true,
    getToken = req => {
      // Token extraction from multiple sources
      if (req.headers.authorization?.startsWith('Bearer ')) {
        return req.headers.authorization.split(' ')[1];
      }
      if (req.cookies?.jwtToken) {
        return req.cookies.jwtToken;
      }
      return null;
    },
    onError = (err, req, res, next) => {
      // Enhanced error responses
      const statusMap = {
        TokenExpiredError: 401,
        TokenInvalidatedError: 401,
        InvalidTokenError: 403,
        JWTManagerError: 403
      };
      
      res.status(statusMap[err.name] || 500).json({
        error: err.message,
        code: err.code || 'AUTH_ERROR',
        timestamp: Date.now()
      });
    }
  } = options;

  return async function(req, res, next) {
    try {
      // Add security headers
      res.set({
        'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin'
      });

      const token = getToken(req);
      
      if (!token) {
        if (credentialsRequired) {
          throw new InvalidTokenError('No authentication token provided');
        }
        return next();
      }

      // Verify token with optional MFA check
      const decoded = await jwtManager.verifyToken(token, {
        code: req.body?.mfaCode
      });
      
      // Attach user context to request
      req.user = {
        id: decoded.sub,
        roles: decoded.roles,
        permissions: decoded.permissions,
        meta: decoded
      };

      // Role-based access control
      if (options.roles) {
        const hasRoles = await jwtManager.hasRoles(token, options.roles);
        if (!hasRoles) {
          throw new JWTManagerError('Insufficient privileges', 'ROLE_REQUIRED');
        }
      }

      // Permission-based access control
      if (options.permissions) {
        const hasPermissions = await jwtManager.hasPermissions(token, options.permissions);
        if (!hasPermissions) {
          throw new JWTManagerError('Insufficient permissions', 'PERMISSION_REQUIRED');
        }
      }

      next();
    } catch (error) {
      // Audit logging for security events
      if (error.code === 'ROLE_REQUIRED' || error.code === 'PERMISSION_REQUIRED') {
        jwtManager.auditLogger.log('AUTHZ_FAILURE', {
          path: req.path,
          user: req.user?.id,
          ip: req.ip
        });
      }
      
      onError(error, req, res, next);
    }
  };
};


// RBAC middleware helpers
JWTManager.requireRoles = function (requiredRoles = []) {
  return (req, res, next) => {
    if (!req.user || !req.user.roles) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const hasAllRoles = requiredRoles.every((role) =>
      req.user.roles.includes(role)
    );

    if (hasAllRoles) {
      return next();
    }

    return res.status(403).json({ error: "Insufficient roles" });
  };
};

JWTManager.requirePermissions = function (requiredPermissions = []) {
  return (req, res, next) => {
    if (!req.user || !req.user.permissions) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const hasAllPermissions = requiredPermissions.every((permission) =>
      req.user.permissions.includes(permission)
    );

    if (hasAllPermissions) {
      return next();
    }

    return res.status(403).json({ error: "Insufficient permissions" });
  };
};

// NEW: Validation Endpoint for Microservices
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

// NEW: Testing Utilities
JWTManager.createMockProvider = function() {
  return {
    generateToken: (userId) => `mock-token-${userId}-${Date.now()}`,
    verifyToken: (token) => ({ sub: token.split('-')[2] }),
    createMiddleware: () => (req, res, next) => next(),
    // ... other mock methods
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
  InvalidationError,
};

module.exports = JWTManager;
