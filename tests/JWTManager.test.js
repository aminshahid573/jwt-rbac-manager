// tests/JWTManager.test.js
const JWTManager = require('../index');

describe('JWTManager', () => {
  let jwtManager;
  const testUserId = 'test-123';
  const testRoles = ['admin', 'editor'];
  
  beforeEach(() => {
    jwtManager = new JWTManager({
      secretKey: 'test-secret-key',
      tokenExpiration: '1h',
      refreshExpiration: '7d',
      issuer: 'test-issuer'
    });
  });

  describe('generateToken', () => {
    test('should generate valid token and refresh token', () => {
      const result = jwtManager.generateToken(testUserId, testRoles);
      
      expect(result).toHaveProperty('token');
      expect(result).toHaveProperty('refreshToken');
      expect(result).toHaveProperty('expiresIn');
      expect(result).toHaveProperty('refreshExpiresIn');
      expect(typeof result.token).toBe('string');
      expect(typeof result.refreshToken).toBe('string');
    });

    test('should throw error if userId is not provided', () => {
      expect(() => {
        jwtManager.generateToken();
      }).toThrow('User ID is required');
    });

    test('should include roles in the token payload', () => {
      const result = jwtManager.generateToken(testUserId, testRoles);
      const decoded = jwtManager.verifyToken(result.token);
      
      expect(decoded).toHaveProperty('roles');
      expect(decoded.roles).toEqual(testRoles);
    });

    test('should include derived permissions in the token payload', () => {
      const result = jwtManager.generateToken(testUserId, testRoles);
      const decoded = jwtManager.verifyToken(result.token);
      
      expect(decoded).toHaveProperty('permissions');
      expect(decoded.permissions).toContain('read:all');
      expect(decoded.permissions).toContain('write:all');
    });
  });

  describe('verifyToken', () => {
    test('should verify and decode a valid token', () => {
      const { token } = jwtManager.generateToken(testUserId, testRoles);
      const decoded = jwtManager.verifyToken(token);
      
      expect(decoded).toHaveProperty('sub', testUserId);
      expect(decoded).toHaveProperty('roles');
      expect(decoded).toHaveProperty('iat');
      expect(decoded).toHaveProperty('exp');
      expect(decoded).toHaveProperty('iss', 'test-issuer');
    });

    test('should throw error for invalid token', () => {
      expect(() => {
        jwtManager.verifyToken('invalid-token');
      }).toThrow('Token verification failed');
    });
  });

  describe('refreshToken', () => {
    test('should generate new tokens with a valid refresh token', () => {
      const { refreshToken } = jwtManager.generateToken(testUserId, testRoles);
      const newTokens = jwtManager.refreshToken(refreshToken);
      
      expect(newTokens).toHaveProperty('token');
      expect(newTokens).toHaveProperty('refreshToken');
      expect(typeof newTokens.token).toBe('string');
      expect(typeof newTokens.refreshToken).toBe('string');
    });

    test('should throw error for invalid refresh token', () => {
      expect(() => {
        jwtManager.refreshToken('invalid-token');
      }).toThrow('Token refresh failed');
    });

    test('should throw error if using an access token as refresh token', () => {
      const { token } = jwtManager.generateToken(testUserId, testRoles);
      
      expect(() => {
        jwtManager.refreshToken(token);
      }).toThrow('Invalid refresh token');
    });
  });

  describe('hasRoles', () => {
    test('should return true if token has all required roles', () => {
      const { token } = jwtManager.generateToken(testUserId, testRoles);
      
      expect(jwtManager.hasRoles(token, ['admin'])).toBe(true);
      expect(jwtManager.hasRoles(token, ['editor'])).toBe(true);
      expect(jwtManager.hasRoles(token, ['admin', 'editor'])).toBe(true);
    });

    test('should return false if token does not have all required roles', () => {
      const { token } = jwtManager.generateToken(testUserId, ['user']);
      
      expect(jwtManager.hasRoles(token, ['admin'])).toBe(false);
      expect(jwtManager.hasRoles(token, ['user', 'admin'])).toBe(false);
    });
  });

  describe('hasPermissions', () => {
    test('should return true if token has all required permissions', () => {
      const { token } = jwtManager.generateToken(testUserId, ['admin']);
      
      expect(jwtManager.hasPermissions(token, ['read:all'])).toBe(true);
      expect(jwtManager.hasPermissions(token, ['write:all'])).toBe(true);
      expect(jwtManager.hasPermissions(token, ['read:all', 'write:all'])).toBe(true);
    });

    test('should return false if token does not have all required permissions', () => {
      const { token } = jwtManager.generateToken(testUserId, ['user']);
      
      expect(jwtManager.hasPermissions(token, ['write:all'])).toBe(false);
      expect(jwtManager.hasPermissions(token, ['read:all', 'write:all'])).toBe(false);
    });
  });

  describe('invalidateToken', () => {
    test('should invalidate a token', () => {
      const { token } = jwtManager.generateToken(testUserId, testRoles);
      const result = jwtManager.invalidateToken(token);
      
      expect(result).toHaveProperty('invalidated', true);
      expect(result).toHaveProperty('expiresAt');
      expect(result.expiresAt).toBeInstanceOf(Date);
    });
  });

  describe('constructor', () => {
    test('should initialize with default options', () => {
      const manager = new JWTManager();
      expect(manager.algorithm).toBe('HS256');
      expect(manager.tokenExpiration).toBe('1h');
      expect(manager.refreshExpiration).toBe('7d');
      expect(manager.issuer).toBe('jwt-manager');
    });

    test('should throw error for asymmetric algorithms without keys', () => {
      expect(() => {
        new JWTManager({ algorithm: 'RS256' });
      }).toThrow('RS256 requires both privateKey and publicKey');
    });
  });

  describe('addRole', () => {
    test('should add new role with permissions', () => {
      jwtManager.addRole('supervisor', ['read:all', 'approve:items']);
      const { token } = jwtManager.generateToken(testUserId, ['supervisor']);
      const decoded = jwtManager.verifyToken(token);
      
      expect(decoded.permissions).toContain('read:all');
      expect(decoded.permissions).toContain('approve:items');
    });
  });

  describe('token expiration', () => {
    test('should respect custom expiration times', () => {
      const { token } = jwtManager.generateToken(testUserId, testRoles, {
        expiresIn: '2h'
      });
      const decoded = jwtManager.verifyToken(token);
      
      const twoHoursFromNow = Math.floor(Date.now() / 1000) + (2 * 60 * 60);
      expect(decoded.exp).toBeCloseTo(twoHoursFromNow, -1);
    });

    test('should use role-specific expiration times', () => {
      const { token } = jwtManager.generateToken(testUserId, ['temporary'], {
        temporaryExpiration: '15m'
      });
      const decoded = jwtManager.verifyToken(token);
      
      const fifteenMinsFromNow = Math.floor(Date.now() / 1000) + (15 * 60);
      expect(decoded.exp).toBeCloseTo(fifteenMinsFromNow, -1);
    });
  });

  describe('custom claims', () => {
    test('should include custom claims in token', () => {
      const customClaims = {
        department: 'IT',
        location: 'HQ'
      };
      
      const { token } = jwtManager.generateToken(testUserId, testRoles, {
        customClaims
      });
      const decoded = jwtManager.verifyToken(token);
      
      expect(decoded.department).toBe('IT');
      expect(decoded.location).toBe('HQ');
    });

    test('should not override protected claims', () => {
      const customClaims = {
        sub: 'fake-id',
        iat: 12345
      };
      
      const { token } = jwtManager.generateToken(testUserId, testRoles, {
        customClaims
      });
      const decoded = jwtManager.verifyToken(token);
      
      expect(decoded.sub).toBe(testUserId);
      expect(decoded.iat).not.toBe(12345);
    });
  });

  describe('middleware', () => {
    test('should create Express middleware', () => {
      const middleware = JWTManager.createMiddleware(jwtManager);
      expect(typeof middleware).toBe('function');
    });

    test('should handle unauthorized requests', async () => {
      const middleware = JWTManager.createMiddleware(jwtManager);
      const req = { headers: {} };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
      const next = jest.fn();

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: 'No token provided' });
    });

    test('should pass valid tokens', async () => {
      const { token } = jwtManager.generateToken(testUserId, testRoles);
      const middleware = JWTManager.createMiddleware(jwtManager);
      const req = {
        headers: {
          authorization: `Bearer ${token}`
        }
      };
      const res = {};
      const next = jest.fn();

      await middleware(req, res, next);

      expect(req.user).toBeDefined();
      expect(req.user.sub).toBe(testUserId);
      expect(next).toHaveBeenCalled();
    });
  });
});