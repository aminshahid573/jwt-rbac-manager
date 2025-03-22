const jwt = require("jsonwebtoken");
const crypto = require("crypto");

// Base adapter class for storage backends
class BaseAdapter {
  constructor() {
    if (this.constructor === BaseAdapter) {
      throw new Error("BaseAdapter cannot be instantiated directly");
    }
  }

  async get(key) {
    throw new Error("Method not implemented");
  }
  async set(key, value, options = {}) {
    throw new Error("Method not implemented");
  }
  async del(key) {
    throw new Error("Method not implemented");
  }
  async hSet(hashKey, field, value) {
    throw new Error("Method not implemented");
  }
  async hGetAll(hashKey) {
    throw new Error("Method not implemented");
  }
  async hDel(hashKey, field) {
    throw new Error("Method not implemented");
  }
  async incr(key) {
    throw new Error("Method not implemented");
  }
  async expire(key, seconds) {
    throw new Error("Method not implemented");
  }
}

// In-memory adapter implementation (default)
class MemoryAdapter extends BaseAdapter {
  constructor() {
    super();
    this.store = new Map();
    this.hashes = new Map();
    this.counters = new Map();
    this.expirations = new Map();
  }

  async get(key) {
    if (this._isExpired(key)) {
      this.store.delete(key);
      return null;
    }
    return this.store.get(key);
  }

  async set(key, value, options = {}) {
    this.store.set(key, value);

    if (options.EX) {
      const expiry = Date.now() + options.EX * 1000;
      this.expirations.set(key, expiry);
    }

    return true;
  }

  async del(key) {
    this.expirations.delete(key);
    return this.store.delete(key);
  }

  async hSet(hashKey, field, value) {
    if (!this.hashes.has(hashKey)) {
      this.hashes.set(hashKey, new Map());
    }
    this.hashes.get(hashKey).set(field, value);
    return true;
  }

  async hGetAll(hashKey) {
    if (!this.hashes.has(hashKey)) {
      return {};
    }

    const result = {};
    this.hashes.get(hashKey).forEach((value, key) => {
      result[key] = value;
    });

    return result;
  }

  async hDel(hashKey, field) {
    if (this.hashes.has(hashKey)) {
      return this.hashes.get(hashKey).delete(field);
    }
    return false;
  }

  async incr(key) {
    const current = this.counters.get(key) || 0;
    this.counters.set(key, current + 1);
    return current + 1;
  }

  async expire(key, seconds) {
    const expiry = Date.now() + seconds * 1000;
    this.expirations.set(key, expiry);
    return true;
  }

  _isExpired(key) {
    const expiry = this.expirations.get(key);
    return expiry && expiry < Date.now();
  }
}

// Redis adapter implementation
class RedisAdapter extends BaseAdapter {
  constructor(redisClient) {
    super();
    if (!redisClient) {
      throw new Error("Redis client is required");
    }
    this.client = redisClient;
  }

  async get(key) {
    return this.client.get(key);
  }

  async set(key, value, options = {}) {
    if (options.EX) {
      return this.client.set(key, value, "EX", options.EX);
    }
    return this.client.set(key, value);
  }

  async del(key) {
    return this.client.del(key);
  }

  async hSet(hashKey, field, value) {
    return this.client.hSet(hashKey, field, value);
  }

  async hGetAll(hashKey) {
    return this.client.hGetAll(hashKey);
  }

  async hDel(hashKey, field) {
    return this.client.hDel(hashKey, field);
  }

  async incr(key) {
    return this.client.incr(key);
  }

  async expire(key, seconds) {
    return this.client.expire(key, seconds);
  }
}

// MongoDB adapter implementation
class MongoAdapter extends BaseAdapter {
  constructor(options) {
    super();
    this.collection = options.collection;
    if (!this.collection) {
      throw new Error("MongoDB collection is required");
    }
  }

  async get(key) {
    const doc = await this.collection.findOne({ _id: key });
    if (!doc) return null;

    if (doc.expiry && doc.expiry < new Date()) {
      await this.del(key);
      return null;
    }

    return doc.value;
  }

  async set(key, value, options = {}) {
    let expiry = null;
    if (options.EX) {
      expiry = new Date(Date.now() + options.EX * 1000);
    }

    await this.collection.updateOne(
      { _id: key },
      { $set: { value, expiry } },
      { upsert: true }
    );

    return true;
  }

  async del(key) {
    const result = await this.collection.deleteOne({ _id: key });
    return result.deletedCount > 0;
  }

  async hSet(hashKey, field, value) {
    const update = {};
    update[`data.${field}`] = value;

    await this.collection.updateOne(
      { _id: hashKey, type: "hash" },
      { $set: update },
      { upsert: true }
    );

    return true;
  }

  async hGetAll(hashKey) {
    const doc = await this.collection.findOne({ _id: hashKey, type: "hash" });
    return doc?.data || {};
  }

  async hDel(hashKey, field) {
    const update = {};
    update[`data.${field}`] = 1;

    const result = await this.collection.updateOne(
      { _id: hashKey, type: "hash" },
      { $unset: update }
    );

    return result.modifiedCount > 0;
  }

  async incr(key) {
    const result = await this.collection.findOneAndUpdate(
      { _id: key, type: "counter" },
      { $inc: { value: 1 } },
      { upsert: true, returnDocument: "after" }
    );

    return result.value?.value || 1;
  }

  async expire(key, seconds) {
    const expiry = new Date(Date.now() + seconds * 1000);

    const result = await this.collection.updateOne(
      { _id: key },
      { $set: { expiry } }
    );

    return result.modifiedCount > 0;
  }
}

// SQL adapter implementation
class SqlAdapter extends BaseAdapter {
  constructor(options) {
    super();
    this.db = options.db;
    this.tableName = options.tableName || "jwt_store";

    if (!this.db) {
      throw new Error("SQL database connection is required");
    }

    this._initTable();
  }

  async _initTable() {
    try {
      await this.db.query(`
        CREATE TABLE IF NOT EXISTS ${this.tableName} (
          key VARCHAR(255) PRIMARY KEY,
          value TEXT,
          type VARCHAR(20),
          hash_field VARCHAR(255),
          expiry TIMESTAMP NULL
        )
      `);

      await this.db.query(`
        CREATE INDEX IF NOT EXISTS idx_${this.tableName}_expiry 
        ON ${this.tableName}(expiry)
      `);
    } catch (error) {
      console.error("Error initializing SQL table:", error);
    }
  }

  async get(key) {
    const query = `
      SELECT value FROM ${this.tableName} 
      WHERE key = ? AND (expiry IS NULL OR expiry > ?)
    `;

    const result = await this.db.query(query, [key, new Date()]);
    if (!result.rows || result.rows.length === 0) return null;

    return result.rows[0].value;
  }

  async set(key, value, options = {}) {
    let expiry = null;
    if (options.EX) {
      expiry = new Date(Date.now() + options.EX * 1000);
    }

    const query = `
      INSERT INTO ${this.tableName} (key, value, type, expiry)
      VALUES (?, ?, 'string', ?)
      ON DUPLICATE KEY UPDATE value = ?, expiry = ?
    `;

    await this.db.query(query, [key, value, expiry, value, expiry]);
    return true;
  }

  async del(key) {
    const query = `DELETE FROM ${this.tableName} WHERE key = ?`;
    const result = await this.db.query(query, [key]);
    return result.affectedRows > 0;
  }

  async hSet(hashKey, field, value) {
    const compositeKey = `${hashKey}:${field}`;

    const query = `
      INSERT INTO ${this.tableName} (key, value, type, hash_field)
      VALUES (?, ?, 'hash', ?)
      ON DUPLICATE KEY UPDATE value = ?
    `;

    await this.db.query(query, [compositeKey, value, field, value]);
    return true;
  }

  async hGetAll(hashKey) {
    const query = `
      SELECT hash_field, value FROM ${this.tableName}
      WHERE key LIKE ? AND type = 'hash'
    `;

    const result = await this.db.query(query, [`${hashKey}:%`]);
    if (!result.rows) return {};

    const hashData = {};
    for (const row of result.rows) {
      hashData[row.hash_field] = row.value;
    }

    return hashData;
  }

  async hDel(hashKey, field) {
    const compositeKey = `${hashKey}:${field}`;

    const query = `DELETE FROM ${this.tableName} WHERE key = ? AND type = 'hash'`;
    const result = await this.db.query(query, [compositeKey]);

    return result.affectedRows > 0;
  }

  async incr(key) {
    const getQuery = `
      SELECT value FROM ${this.tableName}
      WHERE key = ? AND type = 'counter'
    `;

    const result = await this.db.query(getQuery, [key]);
    let currentValue = 0;

    if (result.rows && result.rows.length > 0) {
      currentValue = parseInt(result.rows[0].value, 10) || 0;
    }

    const newValue = currentValue + 1;

    const updateQuery = `
      INSERT INTO ${this.tableName} (key, value, type)
      VALUES (?, ?, 'counter')
      ON DUPLICATE KEY UPDATE value = ?
    `;

    await this.db.query(updateQuery, [
      key,
      newValue.toString(),
      newValue.toString(),
    ]);

    return newValue;
  }

  async expire(key, seconds) {
    const expiry = new Date(Date.now() + seconds * 1000);

    const query = `
      UPDATE ${this.tableName}
      SET expiry = ?
      WHERE key = ?
    `;

    const result = await this.db.query(query, [expiry, key]);
    return result.affectedRows > 0;
  }
}

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
    this.algorithm = options.algorithm || "RS256";

    if (this.algorithm.startsWith("HS")) {
      this.secretKey =
        options.secretKey || crypto.randomBytes(32).toString("hex");
      this.publicKey = this.secretKey;
    } else {
      this.privateKey = options.privateKey;
      this.publicKey = options.publicKey;

      if (!this.privateKey || !this.publicKey) {
        throw new Error(
          `${this.algorithm} requires both privateKey and publicKey`
        );
      }
    }

    this.tokenExpiration = options.tokenExpiration || "15m";
    this.refreshExpiration = options.refreshExpiration || "7d";
    this.issuer = options.issuer || "jwt-manager";
    this.enforceIat =
      options.enforceIat !== undefined ? options.enforceIat : true;

    this.tokenBlacklist = options.tokenBlacklist || new MemoryAdapter();
    this.refreshTokenLimiter =
      options.refreshTokenLimiter || new MemoryAdapter();

    this.permissionsMap = options.permissionsMap || {
      admin: ["read:all", "write:all", "delete:all"],
      editor: ["read:all", "write:own"],
      user: ["read:own"],
    };

    this.auditLogger = options.auditLogger || {
      log: (eventType, data) => {
        if (process.env.NODE_ENV !== 'test') {
          console.log(`[AUDIT] ${eventType}:`, data);
        }
      },
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

    this.sensitiveFields = options.sensitiveFields || [
      "password",
      "ssn",
      "creditCard",
    ];
    this.tokenVersions = new Map();

    // Add token versioning system
    this.tokenVersionPrefix = options.tokenVersionPrefix || "tv_";
    this.roleVersionPrefix = options.roleVersionPrefix || "rv_";

    // Fix 2: Modify key rotation interval
    const defaultRotationInterval = 24 * 60 * 60 * 1000; // 24 hours
    this.keyRotationInterval = Math.min(
        options.keyRotationInterval || defaultRotationInterval,
        2147483647 // Max safe interval
    );

    // Fix 3: Don't automatically start key rotation in constructor
    this.keyHistory = options.keyHistory || new Map();
    
    // Fix 4: Only initialize key rotation if explicitly enabled
    this.enableKeyRotation = options.enableKeyRotation || false;
    if (this.enableKeyRotation && this.algorithm.startsWith("HS")) {
      this._initializeKeyRotation();
    }

    // Add security headers
    this.securityHeaders = options.securityHeaders || {
      strictTransportSecurity: "max-age=31536000; includeSubDomains",
      contentSecurityPolicy: "default-src 'self'",
    };
  }

  // Fix 5: Separate key rotation initialization
  _initializeKeyRotation() {
    if (this._rotationInterval) {
      clearInterval(this._rotationInterval);
    }

      this._rotateSecretKey();
    
    const interval = Math.min(this.keyRotationInterval, 2147483647);
    this._rotationInterval = setInterval(() => {
      this._rotateSecretKey(false); // false means don't set up another interval
    }, interval);
  }

  // Fix 6: Modified _rotateSecretKey to prevent recursive intervals
  _rotateSecretKey(setupInterval = true) {
    if (this.algorithm.startsWith("HS")) {
      const newKey = crypto.randomBytes(64).toString("hex");
      this.keyHistory.set(Date.now(), this.secretKey);
      this.secretKey = newKey;

      // Cleanup old keys
      const cutoff = Date.now() - this.keyRotationInterval;
      this.keyHistory.forEach((_, timestamp) => {
        if (timestamp < cutoff) this.keyHistory.delete(timestamp);
      });
    }
  }

  // Fix 7: Enhanced cleanup method
  cleanup() {
    if (this._rotationInterval) {
      clearInterval(this._rotationInterval);
      this._rotationInterval = null;
    }
    
    // Clear rate limiting data
    if (this.refreshTokenLimiter instanceof MemoryAdapter) {
        this.refreshTokenLimiter.store.clear();
        this.refreshTokenLimiter.counters.clear();
        this.refreshTokenLimiter.expirations.clear();
    }
    
    // Clear session data
    this.tokenBlacklist.del('sessions:*');
    this.keyHistory.clear();
  }

  async generateToken(userId, roles = ["user"], options = {}) {
    if (!userId) {
      throw new InvalidTokenError("User ID is required");
    }

    const {
      additionalData = {},
      customClaims = {},
      expiresIn = this.tokenExpiration,
      refreshExpiresIn = this.refreshExpiration,
    } = options;

    // Initialize role versions if they don't exist
    roles.forEach(role => {
      if (!this.tokenVersions.has(`${this.roleVersionPrefix}${role}`)) {
        this.tokenVersions.set(`${this.roleVersionPrefix}${role}`, 1);
      }
    });

    const payload = {
      sub: userId,
      roles,
      permissions: this._derivePermissionsFromRoles(roles),
      jti: this._generateTokenId(),
      tv: this._getRoleVersions(roles),
      ...additionalData,
    };

    Object.entries(customClaims).forEach(([key, value]) => {
      if (!["iss", "sub", "iat", "exp", "nbf", "jti"].includes(key)) {
        payload[key] = value;
      }
    });

    const token = jwt.sign(
      payload,
      this.algorithm.startsWith("HS") ? this.secretKey : this.privateKey,
      {
        expiresIn: expiresIn,
        issuer: this.issuer,
        algorithm: this.algorithm,
      }
    );

    // Wait for refresh token generation
    const refreshToken = await this._generateRefreshToken(userId, roles, {
      refreshExpiresIn,
      family: options.family || this._generateTokenId(),
    });

    // Store initial token versions in blacklist
    await Promise.all(
      roles.map(role =>
        this.tokenBlacklist.set(
          `${this.roleVersionPrefix}${role}`,
          this.tokenVersions.get(`${this.roleVersionPrefix}${role}`).toString()
        )
      )
    );

    return {
      token,
      refreshToken,
      expiresIn: this._getExpirationTime(expiresIn),
      refreshExpiresIn: this._getExpirationTime(refreshExpiresIn),
    };
  }

  async verifyToken(token, mfaOptions = {}) {
    try {
      const decoded = jwt.verify(token, this.publicKey, {
        algorithms: [this.algorithm],
      });

      if (this.enforceIat && this.tokenBlacklist) {
        const invalidationTime = await this.tokenBlacklist.get(
          `user:${decoded.sub}:invalidation_time`
        );
        if (invalidationTime && decoded.iat < parseInt(invalidationTime)) {
          throw new TokenInvalidatedError("Token has been invalidated");
        }
      }

      if (this.tokenBlacklist) {
        const tokenId = decoded.jti || decoded.sub;
        const isBlacklisted = await this.tokenBlacklist.get(
          `blacklist:${tokenId}`
        );
        if (isBlacklisted === "true") {
          throw new TokenInvalidatedError("Token has been invalidated");
        }
      }

      if (decoded.mfaRequired && this.mfaProvider) {
        if (!mfaOptions.code) {
          throw new JWTManagerError("MFA required", "MFA_REQUIRED");
        }

        const valid = await this.mfaProvider.verify(
          decoded.sub,
          mfaOptions.code
        );
        if (!valid) {
          this.auditLogger.log("MFA_FAILURE", { userId: decoded.sub });
          throw new JWTManagerError("MFA verification failed", "MFA_FAILED");
        }
      }

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
      } else if (
        error instanceof TokenInvalidatedError ||
        error instanceof JWTManagerError
      ) {
        throw error;
      } else {
        throw new TokenVerificationError(
          `Token verification failed: ${error.message}`
        );
      }
    }
  }

  async refreshToken(refreshToken, options = {}) {
    const hashedToken = crypto
      .createHash("sha512")
      .update(refreshToken)
      .digest("hex");
    const decoded = jwt.decode(refreshToken, { complete: true });

    if (!decoded?.payload?.sub) {
      throw new RefreshTokenError("Invalid refresh token structure");
    }

    const familyData = await this.refreshTokenLimiter.hGetAll(
      `user:${decoded.payload.sub}`
    );
    const familyEntry = Object.values(familyData).find(
      (entry) => entry.token === hashedToken
    );

    if (!familyEntry || Date.now() > familyEntry.expiresAt) {
      throw new RefreshTokenError("Invalid or expired refresh token");
    }

    if (familyEntry.uses >= this.sessionConfig.maxSessions) {
      throw new RefreshTokenError("Maximum session limit reached");
    }

    // Invalidate old token and generate new one
    await this.refreshTokenLimiter.hDel(
      `user:${decoded.payload.sub}`,
      familyEntry.family
    );

    return this.generateToken(decoded.payload.sub, familyEntry.roles, {
      ...options,
      family: familyEntry.family,
    });
  }

  async hasRoles(token, requiredRoles = []) {
    const decoded = await this.verifyToken(token);

    if (!decoded.roles || !Array.isArray(decoded.roles)) {
      return false;
    }

    return requiredRoles.every((role) => decoded.roles.includes(role));
  }

  async hasPermissions(token, requiredPermissions = []) {
    const decoded = await this.verifyToken(token);

    if (!decoded.permissions || !Array.isArray(decoded.permissions)) {
      return false;
    }

    return requiredPermissions.every((permission) =>
      decoded.permissions.includes(permission)
    );
  }

  async invalidateToken(token, options = {}) {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded?.payload?.jti) {
      throw new InvalidationError("Token missing JTI");
    }

    const expiration = decoded.payload.exp
      ? Math.floor((decoded.payload.exp * 1000 - Date.now()) / 1000)
      : 3600;

    await this.tokenBlacklist.set(`blacklist:${decoded.payload.jti}`, "true", {
      EX: expiration,
    });

    if (options.invalidateAll) {
      await this.tokenBlacklist.set(
        `user:${decoded.payload.sub}:invalidation_time`,
        Math.floor(Date.now() / 1000)
      );
    }

    this.auditLogger.log("TOKEN_INVALIDATED", {
      userId: decoded.payload.sub,
      jti: decoded.payload.jti,
    });

    return true;
  }

  async invalidateAllUserTokens(userId) {
    try {
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

  async isBlacklisted(token) {
    try {
      const decoded = jwt.verify(
        token,
        this.algorithm.startsWith("HS") ? this.secretKey : this.publicKey,
        { algorithms: [this.algorithm] }
      );

      if (!this.tokenBlacklist) return false;

      if (this.enforceIat) {
        const invalidationTime = await this.tokenBlacklist.get(
          `user:${decoded.sub}:invalidation_time`
        );

        const parsedTime = parseInt(invalidationTime, 10);
        if (!isNaN(parsedTime) && decoded.iat <= parsedTime) {
          return true;
        }
      }

      const tokenId = decoded.jti || decoded.sub;
      const result = await this.tokenBlacklist.get(`blacklist:${tokenId}`);
      return result === "true";
    } catch (error) {
      return false;
    }
  }

  addRole(role, permissions) {
    this.permissionsMap[role] = permissions;
  }

  async _generateRefreshToken(userId, roles, options) {
    const refreshToken = crypto.randomBytes(64).toString("hex");
    const hashedToken = crypto
      .createHash("sha512")
      .update(refreshToken)
      .digest("hex");
    const expiresAt = this._getExpirationTime(options.refreshExpiresIn);

    await this.refreshTokenLimiter.hSet(
      `user:${userId}`,
      options.family,
      JSON.stringify({
        token: hashedToken,
        expiresAt,
        roles,
        uses: 0,
      })
    );

    await this.refreshTokenLimiter.expire(
      `user:${userId}`,
      Math.floor((expiresAt - Date.now()) / 1000)
    );

    return refreshToken;
  }

  _getExpirationTime(expiresIn) {
    const units = {
      s: 1000,
      m: 60 * 1000,
      h: 60 * 60 * 1000,
      d: 24 * 60 * 60 * 1000,
    };

    const match = expiresIn.match(/^(\d+)([smhd])$/);
    if (!match) throw new JWTManagerError("Invalid expiration format");

    const [, num, unit] = match;
    return Date.now() + num * units[unit];
  }

  _derivePermissionsFromRoles(roles) {
    return roles.reduce((perms, role) => {
      const rolePerms = this.permissionsMap[role] || [];
      return [...new Set([...perms, ...rolePerms])];
    }, []);
  }

  _generateTokenId() {
    return crypto.randomBytes(16).toString("hex");
  }

  _getRoleVersions(roles) {
    return roles.reduce((acc, role) => {
      const version = this.tokenVersions.get(`${this.roleVersionPrefix}${role}`) || 1;
      acc[role] = version;
      return acc;
    }, {});
  }

  async updateRole(role, newPermissions) {
    if (!this.permissionsMap[role]) {
      throw new JWTManagerError(`Role ${role} not found`, "ROLE_NOT_FOUND");
    }

    this.permissionsMap[role] = newPermissions;
    
    // Get current version or start at 0
    const currentVersion = parseInt(
        await this.tokenBlacklist.get(`${this.roleVersionPrefix}${role}`) || "0",
        10
    );
    
    const newVersion = currentVersion + 1;
    
    // Update both in-memory and storage
    this.tokenVersions.set(`${this.roleVersionPrefix}${role}`, newVersion);
    await this.tokenBlacklist.set(
        `${this.roleVersionPrefix}${role}`,
        newVersion.toString()
    );

    this.auditLogger.log("ROLE_UPDATED", {
      role,
      newPermissions,
        version: newVersion
    });

    return { role, version: newVersion };
  }

  async validateTokenVersion(decodedToken) {
    try {
        if (!decodedToken.tv) return true; // If no version info, consider valid

        const validations = await Promise.all(
            Object.entries(decodedToken.tv).map(async ([role, tokenVersion]) => {
          const storedVersion = await this.tokenBlacklist.get(
            `${this.roleVersionPrefix}${role}`
          );
                
                // If no stored version, consider it valid
                if (!storedVersion) return true;
                
                // Compare versions as numbers
                const currentVersion = parseInt(storedVersion, 10);
                return !isNaN(currentVersion) && tokenVersion >= currentVersion;
            })
        );
        
        return validations.every(Boolean);
    } catch (error) {
      this.auditLogger.log("VERSION_VALIDATION_ERROR", { error });
        return true; // On error, allow the token (fail open for version checking)
    }
  }

  async trackSession(userId, tokenData) {
    // Ensure JTI exists before proceeding
    if (!tokenData.jti) {
      throw new Error("Session tracking requires valid JTI");
    }

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

  async invalidateOldestSession(userId) {
    const sessions = await this.getSessions(userId);
    if (sessions.length === 0) return null;

    sessions.sort((a, b) => a.lastAccessed - b.lastAccessed);
    const oldestSession = sessions[0];

    await this.tokenBlacklist.hDel(`sessions:${userId}`, oldestSession.id);
    
    // Instead of trying to invalidate the JTI directly, blacklist the session
    await this.tokenBlacklist.set(
        `blacklist:session:${oldestSession.jti}`,
        "true",
        { EX: 3600 } // 1 hour expiry for the blacklist entry
    );

    return oldestSession.id;
  }

  securityMiddleware() {
    return (req, res, next) => {
      Object.entries(this.securityHeaders).forEach(([header, value]) => {
        res.setHeader(header, value);
      });
      next();
    };
  }

  rateLimitMiddleware(profile = "normal") {
    return async (req, res, next) => {
        try {
      const { requests, window } = this.rateLimitProfiles[profile] || {
        requests: 50,
                window: "5m"
      };

      const windowMs = this._getExpirationTime(window) - Date.now();
      const key = `rate_limit:${req.ip}:${profile}`;

            let count;
            if (this.refreshTokenLimiter instanceof MemoryAdapter) {
                count = await this.refreshTokenLimiter.incr(key);
                if (count === 1) {
                    await this.refreshTokenLimiter.expire(key, Math.floor(windowMs / 1000));
                }
            } else {
                count = await this.refreshTokenLimiter.incr(key);
                await this.refreshTokenLimiter.expire(key, Math.floor(windowMs / 1000));
            }

      if (count > requests) {
        this.auditLogger.log("RATE_LIMIT_EXCEEDED", { ip: req.ip });
                res.status(429).json({
                    error: "Too many requests",
                    code: "RATE_LIMITED",
                    retryAfter: Math.floor(windowMs / 1000)
                });
                return; // Important: return here to prevent hanging
      }

      next();
        } catch (error) {
            this.auditLogger.log("RATE_LIMIT_ERROR", { 
                error: error.message,
                ip: req.ip 
            });
            next(error);
        }
    };
  }
  async analyzeTokenRisk(token) {
    const decoded = await this.verifyToken(token);

    return {
      riskScore: Math.random(),
      lastLocation: decoded.geo || "Unknown",
      deviceMatch: true,
      unusualActivity: false,
    };
  }

  generateCompressedToken(userId, roles, options = {}) {
    const payload = this._createCompactPayload(userId, roles, options);
    return jwt.sign(payload, this.secretKey, {
      algorithm: "HS256",
      expiresIn: options.expiresIn || this.tokenExpiration,
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

JWTManager.createMiddleware = function (jwtManager, options = {}) {
  const {
    credentialsRequired = true,
    getToken = (req) => {
      if (req.headers.authorization?.startsWith("Bearer ")) {
        return req.headers.authorization.split(" ")[1];
      }
      if (req.cookies?.jwtToken) {
        return req.cookies.jwtToken;
      }
      return null;
    },
    onError = (err, req, res, next) => {
      const statusMap = {
        TokenExpiredError: 401,
        TokenInvalidatedError: 401,
        InvalidTokenError: 403,
        JWTManagerError: 403,
      };

      res.status(statusMap[err.name] || 500).json({
        error: err.message,
        code: err.code || "AUTH_ERROR",
        timestamp: Date.now(),
      });
    },
  } = options;

  return async function (req, res, next) {
    try {
      res.set({
        "Strict-Transport-Security":
          "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy":
          "default-src 'self'; script-src 'self'; object-src 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Cache-Control":
          "no-store, no-cache, must-revalidate, proxy-revalidate",
      });

      const token = getToken(req);

      if (!token) {
        if (credentialsRequired) {
          throw new InvalidTokenError("No authentication token provided");
        }
        return next();
      }

      const decoded = await jwtManager.verifyToken(token, {
        code: req.body?.mfaCode,
      });

      req.user = {
        id: decoded.sub,
        roles: decoded.roles,
        permissions: decoded.permissions,
        meta: decoded,
      };

      if (options.roles) {
        const hasRoles = await jwtManager.hasRoles(token, options.roles);
        if (!hasRoles) {
          throw new JWTManagerError("Insufficient privileges", "ROLE_REQUIRED");
        }
      }

      if (options.permissions) {
        const hasPermissions = await jwtManager.hasPermissions(
          token,
          options.permissions
        );
        if (!hasPermissions) {
          throw new JWTManagerError(
            "Insufficient permissions",
            "PERMISSION_REQUIRED"
          );
        }
      }

      next();
    } catch (error) {
      if (
        error.code === "ROLE_REQUIRED" ||
        error.code === "PERMISSION_REQUIRED"
      ) {
        jwtManager.auditLogger.log("AUTHZ_FAILURE", {
          path: req.path,
          user: req.user?.id,
          ip: req.ip,
        });
      }

      onError(error, req, res, next);
    }
  };
};

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

JWTManager.createValidationEndpoint = function (jwtManager) {
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

JWTManager.createMockProvider = function () {
  return {
    generateToken: (userId) => `mock-token-${userId}-${Date.now()}`,
    verifyToken: (token) => ({ sub: token.split("-")[2] }),
    createMiddleware: () => (req, res, next) => next(),
  };
};

JWTManager.errors = {
  JWTManagerError,
  TokenExpiredError,
  InvalidTokenError,
  TokenVerificationError,
  TokenInvalidatedError,
  RefreshTokenError,
  InvalidationError,
};

module.exports = {
  BaseAdapter,
  MemoryAdapter,
  RedisAdapter,
  MongoAdapter,
  SqlAdapter,
  JWTManager,
  JWTManagerError,
  TokenExpiredError,
  InvalidTokenError,
  TokenVerificationError,
  TokenInvalidatedError,
  RefreshTokenError,
  InvalidationError,
};
