// tests/JWTManager.test.js
const JWTManager = require('../index.js');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Mock redis client for testing
const mockRedisClient = {
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
    incr: jest.fn(),
    expire: jest.fn()
};

describe('JWTManager', () => {
    let jwtManager;
    const userId = 'testUser';
    const roles = ['user'];

    beforeEach(() => {
        jest.clearAllMocks(); // Clear mock function calls before each test

        jwtManager = new JWTManager({
            algorithm: 'HS256',
            secretKey: 'testSecret',
            tokenExpiration: '1h',
            refreshExpiration: '7d',
            issuer: 'testIssuer',
            permissionsMap: {
                user: ['read:own'],
                admin: ['read:all', 'write:all']
            },
            tokenBlacklist: mockRedisClient,
            refreshTokenLimiter: mockRedisClient,
            enforceIat: true
        });
    });

    it('should generate a JWT token and refresh token', () => {
        const { token, refreshToken } = jwtManager.generateToken(userId, roles);
        expect(token).toBeDefined();
        expect(refreshToken).toBeDefined();
    });

    it('should verify a JWT token', async () => {
        const { token } = jwtManager.generateToken(userId, roles);
        const decoded = await jwtManager.verifyToken(token);
        expect(decoded.sub).toBe(userId);
        expect(decoded.roles).toEqual(roles);
    });

    it('should throw an error when verifying an expired JWT token', async () => {
        const expiredJwtManager = new JWTManager({
            algorithm: 'HS256',
            secretKey: 'testSecret',
            tokenExpiration: '1s', // Expire after 1 second
            refreshExpiration: '7d',
            issuer: 'testIssuer',
            permissionsMap: {
                user: ['read:own']
            },
            tokenBlacklist: mockRedisClient,
            refreshTokenLimiter: mockRedisClient,
            enforceIat: true
        });
        const { token } = expiredJwtManager.generateToken(userId, roles);

        // Wait for the token to expire
        await new Promise(resolve => setTimeout(resolve, 1500));

        await expect(expiredJwtManager.verifyToken(token)).rejects.toThrow('Token has expired');
    });

    it('should refresh a JWT token', async () => {
        const { refreshToken } = jwtManager.generateToken(userId, roles);

        // Mock Redis to allow refresh
        mockRedisClient.get.mockResolvedValue(null);
        mockRedisClient.incr.mockResolvedValue(1); // First refresh attempt

        const { token: newToken, refreshToken: newRefreshToken } = await jwtManager.refreshToken(refreshToken);
        expect(newToken).toBeDefined();
        expect(newRefreshToken).toBeDefined();
    });

    it('should throw an error when refreshing with an invalid refresh token', async () => {
        await expect(jwtManager.refreshToken('invalidRefreshToken')).rejects.toThrow('Invalid refresh token');
    });

    it('should check if a user has required roles', async () => {
        const { token } = jwtManager.generateToken(userId, roles);
        const hasRoles = await jwtManager.hasRoles(token, ['user']);
        expect(hasRoles).toBe(true);

        const hasAdminRole = await jwtManager.hasRoles(token, ['admin']);
        expect(hasAdminRole).toBe(false);
    });

    it('should check if a user has required permissions', async () => {
        const { token } = jwtManager.generateToken(userId, roles);
        const hasPermission = await jwtManager.hasPermissions(token, ['read:own']);
        expect(hasPermission).toBe(true);

        const hasAdminPermission = await jwtManager.hasPermissions(token, ['read:all']);
        expect(hasAdminPermission).toBe(false);
    });

    it('should invalidate a token', async () => {
        const { token } = jwtManager.generateToken(userId, roles);
        mockRedisClient.get.mockResolvedValue(null);

        const result = await jwtManager.invalidateToken(token);
        expect(result.invalidated).toBe(true);
        expect(mockRedisClient.set).toHaveBeenCalled();
    });

    it('should invalidate all tokens for a user', async () => {
        const result = await jwtManager.invalidateAllUserTokens(userId);
        expect(result.invalidated).toBe(true);
        expect(mockRedisClient.set).toHaveBeenCalled();
    });

    it('should check if a token is blacklisted', async () => {
        const { token } = jwtManager.generateToken(userId, roles);
        mockRedisClient.get.mockResolvedValue('true'); // Mock blacklisted token

        const isBlacklisted = await jwtManager.isBlacklisted(token);
        expect(isBlacklisted).toBe(true);
    });

    it('should allow adding new roles at runtime', () => {
        jwtManager.addRole('moderator', ['read:all', 'write:own', 'moderate:comments']);
        expect(jwtManager.permissionsMap.moderator).toEqual(['read:all', 'write:own', 'moderate:comments']);
    });

    it('should enforce iat based token invalidation', async () => {
        const { token } = jwtManager.generateToken(userId, roles);
        const decoded = jwt.decode(token);

        mockRedisClient.get.mockResolvedValue((decoded.iat - 1000).toString()); // Simulate token issued before invalidation time
        
        const isBlacklisted = await jwtManager.isBlacklisted(token);
        expect(isBlacklisted).toBe(true);
    });

    it('should handle token refresh rate limiting', async () => {
        const { refreshToken } = jwtManager.generateToken(userId, roles);

        mockRedisClient.get.mockResolvedValue(null);
        mockRedisClient.incr.mockResolvedValue(11); // Simulate rate limit exceeded

        await expect(jwtManager.refreshToken(refreshToken)).rejects.toThrow('Too many refresh attempts');
    });

    it('should handle token refresh when refresh token is blacklisted', async () => {
        const { refreshToken } = jwtManager.generateToken(userId, roles);

        mockRedisClient.get.mockResolvedValue('true'); // Simulate blacklisted refresh token

        await expect(jwtManager.refreshToken(refreshToken)).rejects.toThrow('Refresh token has been revoked');
    });
});
