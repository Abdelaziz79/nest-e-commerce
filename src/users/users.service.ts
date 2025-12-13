// src/users/users.service.ts
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import {
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectConnection, InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import type { Cache } from 'cache-manager';
import { Connection, Model } from 'mongoose';
import { createApiFeatures } from 'src/common/utils/api-features';
import { NotificationHelperService } from 'src/notifications/notification-helper.service';
import {
  AddAddressInput,
  BanUserInput,
  CreateUserInput,
  UpdateAddressInput,
  UpdateUserInput,
  UpdateUserRoleInput,
  UpdateUserStatusInput,
  UsersFilterInput,
} from './dto/user.input';
import { User, UserRole, UserStatus } from './schemas/user.schema';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);
  private readonly MAX_ADDRESSES = 10;
  private readonly CACHE_TTL = 30000; // 30 seconds
  private readonly CACHE_USER_PREFIX = 'user:';
  private readonly CACHE_JWT_PREFIX = 'jwt_user:';

  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    @InjectConnection() private readonly connection: Connection,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private readonly notificationHelper: NotificationHelperService,
  ) {}

  // =================================================================
  // PRIVATE HELPER METHODS
  // =================================================================

  /**
   * Invalidate ALL user-related caches
   * Call this whenever user data changes
   */
  private async invalidateUserCache(userId: string): Promise<void> {
    await Promise.all([
      this.cacheManager.del(`${this.CACHE_USER_PREFIX}${userId}`),
      this.cacheManager.del(`${this.CACHE_JWT_PREFIX}${userId}`),
    ]);
  }

  /**
   * Invalidate JWT cache specifically
   * Call this for critical security changes (ban, suspend, deactivate, role change)
   */
  private async invalidateJwtCache(userId: string): Promise<void> {
    await this.cacheManager.del(`${this.CACHE_JWT_PREFIX}${userId}`);
  }

  /**
   * Find token index by comparing hashed tokens
   */
  private async findTokenIndex(
    storedTokens: string[],
    tokenToMatch: string,
  ): Promise<number> {
    for (let i = 0; i < storedTokens.length; i++) {
      const isMatch = await bcrypt.compare(tokenToMatch, storedTokens[i]);
      if (isMatch) return i;
    }
    return -1;
  }

  /**
   * Check if admin has permission to modify target user
   */
  private async checkAdminPermission(
    adminRole: UserRole,
    targetUserId: string,
  ): Promise<void> {
    const targetUser = await this.userModel.findById(targetUserId);
    if (!targetUser) throw new NotFoundException('Target user not found');

    // Super admins can modify anyone EXCEPT other super admins
    if (
      adminRole === UserRole.SUPER_ADMIN &&
      targetUser.role === UserRole.SUPER_ADMIN
    ) {
      throw new ForbiddenException(
        'Super admins cannot modify other super admins',
      );
    }

    // Regular admins can only modify customers
    if (adminRole === UserRole.ADMIN) {
      if (targetUser.role !== UserRole.CUSTOMER) {
        throw new ForbiddenException(
          'Admins can only modify customer accounts',
        );
      }
    }
  }

  // ==========================================
  // OPTIMIZED QUERIES FOR JWT VALIDATION
  // ==========================================

  /**
   * MINIMAL USER QUERY FOR JWT VALIDATION
   * Only fetches fields needed for security checks
   * Used by JwtStrategy on EVERY authenticated request
   *
   * This is FAST because:
   * 1. Only selects 5 fields (no joins, no large fields)
   * 2. Uses indexed _id lookup
   * 3. Lean query (plain JS object, not Mongoose document)
   */
  async findByIdMinimal(userId: string): Promise<{
    _id: string;
    isActive: boolean;
    status: UserStatus;
    role: UserRole;
    isEmailVerified: boolean;
    twoFactorEnabled: boolean;
    firstName: string;
    lastName: string;
  } | null> {
    const user = await this.userModel
      .findById(userId)
      .select(
        'isActive status role isEmailVerified twoFactorEnabled firstName lastName',
      )
      .lean() // Returns plain JS object (faster than Mongoose document)
      .exec();

    if (!user) return null;

    return {
      ...user,
      _id: user._id.toString(),
    };
  }

  // =================================================================
  // 1. TRANSACTIONAL CREATE (REGISTER)
  // =================================================================

  async create(createUserInput: CreateUserInput): Promise<User> {
    const session = await this.connection.startSession();
    session.startTransaction();

    try {
      // Check email uniqueness
      const existingUser = await this.userModel.findOne({
        email: createUserInput.email,
      });
      if (existingUser) {
        throw new ConflictException('Email already exists');
      }

      // Check username uniqueness
      if (createUserInput.username) {
        const existingUsername = await this.userModel.findOne({
          username: createUserInput.username,
        });
        if (existingUsername) {
          throw new ConflictException('Username already exists');
        }
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(createUserInput.password, 10);

      // Create user
      const user = new this.userModel({
        ...createUserInput,
        password: hashedPassword,
      });

      await user.save({ session });
      await session.commitTransaction();

      this.logger.log(`User created: ${user.email} (${user._id})`);
      return user;
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      await session.endSession();
    }
  }

  // =================================================================
  // 2. SOCIAL LOGIN HELPERS
  // =================================================================

  async findByGoogleId(googleId: string): Promise<User | null> {
    return this.userModel.findOne({ googleId });
  }

  async findByGithubId(githubId: string): Promise<User | null> {
    return this.userModel.findOne({ githubId });
  }

  async linkGoogleAccount(userId: string, googleId: string): Promise<User> {
    const user = await this.userModel.findByIdAndUpdate(
      userId,
      { googleId, isEmailVerified: true, status: UserStatus.ACTIVE },
      { new: true },
    );
    if (!user) throw new NotFoundException('User not found');

    await this.invalidateUserCache(userId);
    return user;
  }

  async linkGithubAccount(userId: string, githubId: string): Promise<User> {
    const user = await this.userModel.findByIdAndUpdate(
      userId,
      { githubId, isEmailVerified: true, status: UserStatus.ACTIVE },
      { new: true },
    );
    if (!user) throw new NotFoundException('User not found');

    await this.invalidateUserCache(userId);
    return user;
  }

  // =================================================================
  // 3. TOKEN MANAGEMENT
  // =================================================================

  /**
   * Find user with refresh tokens (for device tracking)
   */
  async findByIdWithRefreshTokens(userId: string): Promise<User> {
    const user = await this.userModel.findById(userId).select('+refreshTokens');

    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  /**
   * Add refresh token with device information
   */
  async addRefreshToken(
    userId: string,
    refreshToken: string,
    deviceInfo: string = 'Unknown Device',
    expiresIn: string = '7d',
  ): Promise<void> {
    const hashedToken = await bcrypt.hash(refreshToken, 10);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // Clean up expired tokens first
    await this.userModel.findByIdAndUpdate(userId, {
      $pull: {
        refreshTokens: {
          expiresAt: { $lt: new Date() },
        },
      },
    });

    // Add new token with device info
    await this.userModel.findByIdAndUpdate(userId, {
      $push: {
        refreshTokens: {
          token: hashedToken,
          createdAt: new Date(),
          expiresAt,
          deviceInfo,
        },
      },
    });
  }

  async rotateRefreshToken(
    userId: string,
    oldRefreshToken: string,
    newRefreshToken: string,
  ): Promise<User> {
    const user = await this.userModel.findById(userId).select('+refreshTokens');
    if (!user) throw new UnauthorizedException('User not found');

    // Clean expired tokens
    user.refreshTokens = user.refreshTokens.filter(
      (rt) => rt.expiresAt > new Date(),
    );

    // Find the old token
    const tokenIndex = await this.findTokenIndex(
      user.refreshTokens.map((rt) => rt.token),
      oldRefreshToken,
    );

    // If old token is invalid, revoke all tokens (security measure)
    if (tokenIndex === -1) {
      this.logger.warn(
        `Invalid refresh token rotation attempt for user: ${userId}`,
      );
      await this.revokeAllRefreshTokens(userId);
      throw new UnauthorizedException(
        'Invalid Refresh Token - All tokens revoked',
      );
    }

    // Remove old token
    user.refreshTokens.splice(tokenIndex, 1);

    // Add new token
    const hashedNewToken = await bcrypt.hash(newRefreshToken, 10);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    user.refreshTokens.push({
      token: hashedNewToken,
      createdAt: new Date(),
      expiresAt,
    });

    return user.save();
  }

  async revokeRefreshToken(
    userId: string,
    refreshToken: string,
  ): Promise<void> {
    const user = await this.userModel.findById(userId).select('+refreshTokens');
    if (!user) return;

    const tokenIndex = await this.findTokenIndex(
      user.refreshTokens.map((rt) => rt.token),
      refreshToken,
    );

    if (tokenIndex !== -1) {
      user.refreshTokens.splice(tokenIndex, 1);
      await user.save();
    }
  }

  async revokeAllRefreshTokens(userId: string): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      refreshTokens: [],
    });
  }

  // =================================================================
  // 4. READ OPERATIONS (CACHED & STANDARD)
  // =================================================================

  /**
   * CACHED FULL USER QUERY
   * Used when you need complete user data
   * Uses Redis cache with 30s TTL
   */
  async findById(id: string): Promise<User> {
    const cacheKey = `${this.CACHE_USER_PREFIX}${id}`;
    const cachedUser = await this.cacheManager.get<User>(cacheKey);

    if (cachedUser) {
      return cachedUser;
    }

    const user = await this.userModel
      .findById(id)
      .select('-password -refreshTokens')
      .exec();

    if (!user) throw new NotFoundException('User not found');

    await this.cacheManager.set(cacheKey, user.toObject(), this.CACHE_TTL);
    return user;
  }

  async findAll(filters?: UsersFilterInput) {
    const {
      search,
      role,
      status,
      isEmailVerified,
      page = 1,
      limit = 10,
    } = filters || {};

    // Build filter object
    const filterObj: any = {};
    if (role) filterObj.role = role;
    if (status) filterObj.status = status;
    if (isEmailVerified !== undefined)
      filterObj.isEmailVerified = isEmailVerified;

    // Create base query
    const baseQuery = this.userModel.find().select('-password -refreshTokens');

    // Use ApiFeatures class
    const apiFeatures = createApiFeatures(baseQuery, {
      search: {
        searchTerm: search,
        // Use text search (requires text index on schema)
      },
      filters: filterObj,
      sort: {
        defaultSort: search
          ? { score: { $meta: 'textScore' } as any }
          : { createdAt: -1 },
      },
      pagination: {
        page,
        limit,
        maxLimit: 100,
      },
    });

    // Apply all features and execute
    const result = await apiFeatures
      .search()
      .filter()
      .sort()
      .select()
      .paginate()
      .execute();

    return {
      users: result.data,
      total: result.pagination.total,
      page: result.pagination.page,
      limit: result.pagination.limit,
      totalPages: result.pagination.totalPages,
    };
  }

  async findByEmail(email: string): Promise<User> {
    const user = await this.userModel.findOne({ email }).select('+password');
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  // =================================================================
  // 5. WRITE OPERATIONS
  // =================================================================

  /**
   * Update user with appropriate cache invalidation
   */
  async update(
    userId: string,
    updateUserInput: UpdateUserInput & {
      isEmailVerified?: boolean;
      status?: UserStatus;
    },
  ): Promise<User> {
    // Check username uniqueness if updating
    if (updateUserInput.username) {
      const existingUsername = await this.userModel.findOne({
        username: updateUserInput.username,
        _id: { $ne: userId },
      });
      if (existingUsername) {
        throw new ConflictException('Username already exists');
      }
    }

    const user = await this.userModel.findByIdAndUpdate(
      userId,
      { $set: updateUserInput },
      { new: true },
    );

    if (!user) throw new NotFoundException('User not found');

    // CRITICAL: Invalidate JWT cache if status changed
    if (updateUserInput.status) {
      await this.invalidateJwtCache(userId);
    }

    await this.invalidateUserCache(userId);
    return user;
  }

  /**
   * Deactivate account with cache invalidation
   */
  async delete(userId: string): Promise<User> {
    const user = await this.userModel.findByIdAndUpdate(
      userId,
      { isActive: false },
      { new: true },
    );

    if (!user) throw new NotFoundException('User not found');

    // CRITICAL: Invalidate JWT cache so deactivation takes effect
    await this.invalidateJwtCache(userId);
    await this.invalidateUserCache(userId);

    return user;
  }

  // =================================================================
  // 6. ADMIN ACTIONS WITH PERMISSION CHECKS
  // =================================================================

  /**
   * Update role with immediate cache invalidation
   */
  async updateRole(
    updateRoleInput: UpdateUserRoleInput,
    adminRole?: UserRole,
  ): Promise<User> {
    if (adminRole) {
      await this.checkAdminPermission(adminRole, updateRoleInput.userId);

      if (adminRole === UserRole.ADMIN) {
        if (
          updateRoleInput.role === UserRole.ADMIN ||
          updateRoleInput.role === UserRole.SUPER_ADMIN
        ) {
          throw new ForbiddenException(
            'Admins cannot promote users to admin or super admin',
          );
        }
      }

      if (
        adminRole === UserRole.SUPER_ADMIN &&
        updateRoleInput.role === UserRole.SUPER_ADMIN
      ) {
        throw new ForbiddenException(
          'Use promoteToSuperAdmin mutation for promoting to super admin',
        );
      }
    }

    const user = await this.userModel.findByIdAndUpdate(
      updateRoleInput.userId,
      { role: updateRoleInput.role },
      { new: true },
    );

    if (!user) throw new NotFoundException('User not found');

    this.logger.warn(
      `User role updated: ${updateRoleInput.userId} -> ${updateRoleInput.role}`,
    );

    // CRITICAL: Immediately invalidate JWT cache so role change takes effect
    await this.invalidateJwtCache(updateRoleInput.userId);
    await this.invalidateUserCache(updateRoleInput.userId);

    // Send notification
    await this.notificationHelper.notifyAccountSecurity(
      updateRoleInput.userId,
      {
        message: `Your account role has been updated to ${updateRoleInput.role}.`,
      },
    );

    return user;
  }

  async promoteToSuperAdmin(userId: string, promotedBy: string): Promise<User> {
    const targetUser = await this.userModel.findById(userId);
    if (!targetUser) {
      throw new NotFoundException('Target user not found');
    }

    if (targetUser.role === UserRole.SUPER_ADMIN) {
      throw new ConflictException('User is already a super admin');
    }

    const user = await this.userModel.findByIdAndUpdate(
      userId,
      {
        role: UserRole.SUPER_ADMIN,
        status: UserStatus.ACTIVE,
      },
      { new: true },
    );

    if (!user) throw new NotFoundException('User not found');

    this.logger.warn(
      `🚨 CRITICAL: User ${userId} (${user.email}) promoted to SUPER_ADMIN by ${promotedBy}`,
    );

    await this.invalidateUserCache(userId);
    return user;
  }

  /**
   * Update status with immediate cache invalidation
   */
  async updateStatus(
    updateStatusInput: UpdateUserStatusInput,
    adminRole?: UserRole,
  ): Promise<User> {
    if (adminRole) {
      await this.checkAdminPermission(adminRole, updateStatusInput.userId);
    }

    const user = await this.userModel.findByIdAndUpdate(
      updateStatusInput.userId,
      { status: updateStatusInput.status },
      { new: true },
    );

    if (!user) throw new NotFoundException('User not found');

    // CRITICAL: Immediately invalidate JWT cache so status change takes effect
    await this.invalidateJwtCache(updateStatusInput.userId);
    await this.invalidateUserCache(updateStatusInput.userId);

    // Send notification based on status
    if (updateStatusInput.status === UserStatus.SUSPENDED) {
      await this.notificationHelper.notifyAccountSecurity(
        updateStatusInput.userId,
        {
          message:
            'Your account has been suspended. Contact support for more information.',
        },
      );
    }

    return user;
  }

  /**
   * Ban user with immediate cache invalidation
   */
  async banUser(
    banInput: BanUserInput,
    bannedBy: string,
    adminRole?: UserRole,
  ): Promise<User> {
    const session = await this.connection.startSession();
    session.startTransaction();

    try {
      if (adminRole) {
        await this.checkAdminPermission(adminRole, banInput.userId);
      }

      const user = await this.userModel.findByIdAndUpdate(
        banInput.userId,
        {
          status: UserStatus.BANNED,
          banReason: banInput.reason,
          bannedAt: new Date(),
          bannedBy,
          refreshTokens: [], // Revoke all refresh tokens
        },
        { new: true, session },
      );

      if (!user) throw new NotFoundException('User not found');

      await session.commitTransaction();

      this.logger.warn(
        `User banned: ${banInput.userId} - Reason: ${banInput.reason}`,
      );

      // CRITICAL: Immediately invalidate JWT cache so ban takes effect
      await this.invalidateJwtCache(banInput.userId);
      await this.invalidateUserCache(banInput.userId);

      // Send notification
      await this.notificationHelper.notifyAccountSecurity(banInput.userId, {
        message: `Your account has been banned. Reason: ${banInput.reason}. Contact support if you believe this is a mistake.`,
      });

      return user;
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Unban user with cache invalidation
   */
  async unbanUser(userId: string, adminRole?: UserRole): Promise<User> {
    if (adminRole) {
      await this.checkAdminPermission(adminRole, userId);
    }

    const user = await this.userModel.findByIdAndUpdate(
      userId,
      {
        status: UserStatus.ACTIVE,
        banReason: null,
        bannedAt: null,
        bannedBy: null,
      },
      { new: true },
    );

    if (!user) throw new NotFoundException('User not found');

    this.logger.log(`User unbanned: ${userId}`);

    // CRITICAL: Invalidate JWT cache so unban takes effect
    await this.invalidateJwtCache(userId);
    await this.invalidateUserCache(userId);

    // Send notification
    await this.notificationHelper.notifyAccountSecurity(userId, {
      message:
        'Your account has been unbanned. You can now access all features.',
    });

    return user;
  }

  // =================================================================
  // 7. ADDRESS MANAGEMENT
  // =================================================================

  async addAddress(userId: string, addressInput: AddAddressInput) {
    const user = await this.userModel.findById(userId);
    if (!user) throw new NotFoundException('User not found');

    // Check address limit
    if (user.addresses.length >= this.MAX_ADDRESSES) {
      throw new ConflictException(
        `Maximum ${this.MAX_ADDRESSES} addresses allowed`,
      );
    }

    // If new address is default, unset other defaults
    if (addressInput.address.isDefault) {
      await this.userModel.updateOne(
        { _id: userId },
        { $set: { 'addresses.$[].isDefault': false } },
      );
    }

    const updatedUser = await this.userModel.findByIdAndUpdate(
      userId,
      { $push: { addresses: addressInput.address } },
      { new: true },
    );

    await this.invalidateUserCache(userId);
    return updatedUser;
  }

  async updateAddress(
    userId: string,
    addressId: string,
    updateAddressInput: UpdateAddressInput,
  ): Promise<User> {
    // If updating to default, unset other defaults first
    if (updateAddressInput.address.isDefault) {
      await this.userModel.updateOne(
        { _id: userId },
        { $set: { 'addresses.$[].isDefault': false } },
      );
    }

    // Build update fields
    const updateFields: any = {};
    for (const [key, value] of Object.entries(updateAddressInput.address)) {
      updateFields[`addresses.$.${key}`] = value;
    }

    const user = await this.userModel.findOneAndUpdate(
      { _id: userId, 'addresses._id': addressId },
      { $set: updateFields },
      { new: true },
    );

    if (!user) throw new NotFoundException('User or address not found');

    await this.invalidateUserCache(userId);
    return user;
  }

  async deleteAddress(userId: string, addressId: string): Promise<User> {
    const user = await this.userModel.findByIdAndUpdate(
      userId,
      { $pull: { addresses: { _id: addressId } } },
      { new: true },
    );

    if (!user) throw new NotFoundException('User not found');

    await this.invalidateUserCache(userId);
    return user;
  }

  async setDefaultAddress(userId: string, addressId: string): Promise<User> {
    // First, unset all defaults
    await this.userModel.updateOne(
      { _id: userId },
      { $set: { 'addresses.$[].isDefault': false } },
    );

    // Then set the specified address as default
    const user = await this.userModel.findOneAndUpdate(
      { _id: userId, 'addresses._id': addressId },
      { $set: { 'addresses.$.isDefault': true } },
      { new: true },
    );

    if (!user) throw new NotFoundException('User or address not found');

    await this.invalidateUserCache(userId);
    return user;
  }

  // =================================================================
  // 8. LOGIN HELPERS
  // =================================================================

  async updateLastLogin(userId: string): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      lastLogin: new Date(),
      loginAttempts: 0,
    });
  }

  async incrementLoginAttempts(email: string): Promise<void> {
    const user = await this.userModel.findOne({ email });
    if (!user) return;

    const updates: any = { $inc: { loginAttempts: 1 } };

    // Lock account after 5 failed attempts
    if (user.loginAttempts >= 4) {
      updates.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    }

    await this.userModel.findByIdAndUpdate(user._id, updates);
  }

  async isAccountLocked(email: string): Promise<boolean> {
    const user = await this.userModel.findOne({ email });
    if (!user) return false;

    if (user.lockUntil && user.lockUntil > new Date()) {
      return true;
    }

    // If lock expired, reset attempts
    if (user.lockUntil && user.lockUntil <= new Date()) {
      await this.userModel.findByIdAndUpdate(user._id, {
        loginAttempts: 0,
        lockUntil: null,
      });
      return false;
    }

    return false;
  }

  // =================================================================
  // 9. RESET PASSWORD HELPERS
  // =================================================================

  async setPasswordResetToken(
    userId: string,
    hashedToken: string,
    expiresAt: Date,
  ): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      passwordResetToken: hashedToken,
      passwordResetExpires: expiresAt,
    });
  }

  async findByIdForPasswordReset(userId: string): Promise<User | null> {
    const user = await this.userModel
      .findById(userId)
      .select('+passwordResetToken +passwordResetExpires');

    if (!user) return null;

    if (
      !user.passwordResetToken ||
      !user.passwordResetExpires ||
      user.passwordResetExpires < new Date()
    ) {
      return null;
    }

    return user;
  }

  /**
   * Update password with full cache invalidation
   */
  async updatePassword(userId: string, hashedPassword: string): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      password: hashedPassword,
      passwordResetToken: null,
      passwordResetExpires: null,
    });

    // Invalidate ALL caches on password change
    await this.invalidateJwtCache(userId);
    await this.invalidateUserCache(userId);
  }

  // =================================================================
  // 10. TWO-FACTOR AUTHENTICATION
  // =================================================================

  async findByIdWithTwoFactorSecret(userId: string): Promise<User> {
    const user = await this.userModel
      .findById(userId)
      .select('+twoFactorSecret');
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async findByIdWithBackupCodes(userId: string): Promise<User> {
    const user = await this.userModel
      .findById(userId)
      .select('+twoFactorBackupCodes');
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async updateTwoFactorSecret(userId: string, secret: string): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      twoFactorSecret: secret,
    });
    await this.invalidateUserCache(userId);
  }

  /**
   * Enable 2FA with cache invalidation
   */
  async enableTwoFactor(userId: string): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      twoFactorEnabled: true,
      twoFactorEnabledAt: new Date(),
    });

    // Invalidate JWT cache so 2FA status is reflected
    await this.invalidateJwtCache(userId);
    await this.invalidateUserCache(userId);
  }

  /**
   * Disable 2FA with cache invalidation
   */
  async disableTwoFactor(userId: string): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      twoFactorEnabled: false,
      twoFactorSecret: null,
      twoFactorBackupCodes: [],
      twoFactorEnabledAt: null,
      twoFactorBackupCodesUsed: 0,
    });

    // Invalidate JWT cache so 2FA status is reflected
    await this.invalidateJwtCache(userId);
    await this.invalidateUserCache(userId);
  }

  async updateBackupCodes(
    userId: string,
    hashedCodes: string[],
  ): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      twoFactorBackupCodes: hashedCodes,
      twoFactorBackupCodesUsed: 0,
    });
    await this.invalidateUserCache(userId);
  }

  async removeBackupCode(userId: string, index: number): Promise<void> {
    const user = await this.findByIdWithBackupCodes(userId);
    user.twoFactorBackupCodes.splice(index, 1);
    user.twoFactorBackupCodesUsed += 1;
    await user.save();
    await this.invalidateUserCache(userId);
  }
}
