// src/users/users.service.ts - UPDATED VERSION
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

  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    @InjectConnection() private readonly connection: Connection,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  // =================================================================
  // 1. Transactional Create (Register)
  // =================================================================
  async create(createUserInput: CreateUserInput): Promise<User> {
    const session = await this.connection.startSession();
    session.startTransaction();

    try {
      const existingUser = await this.userModel.findOne({
        email: createUserInput.email,
      });
      if (existingUser) {
        throw new ConflictException('Email already exists');
      }

      if (createUserInput.username) {
        const existingUsername = await this.userModel.findOne({
          username: createUserInput.username,
        });
        if (existingUsername) {
          throw new ConflictException('Username already exists');
        }
      }

      const hashedPassword = await bcrypt.hash(createUserInput.password, 10);

      const user = new this.userModel({
        ...createUserInput,
        password: hashedPassword,
      });

      await user.save({ session });
      await session.commitTransaction();
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

    await this.cacheManager.del(`user:${userId}`);
    return user;
  }

  async linkGithubAccount(userId: string, githubId: string): Promise<User> {
    const user = await this.userModel.findByIdAndUpdate(
      userId,
      { githubId, isEmailVerified: true, status: UserStatus.ACTIVE },
      { new: true },
    );
    if (!user) throw new NotFoundException('User not found');

    await this.cacheManager.del(`user:${userId}`);
    return user;
  }

  // =================================================================
  // 3. TOKEN MANAGEMENT
  // =================================================================

  async addRefreshToken(
    userId: string,
    refreshToken: string,
    expiresIn: string = '7d',
  ): Promise<void> {
    const hashedToken = await bcrypt.hash(refreshToken, 10);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await this.userModel.findByIdAndUpdate(userId, {
      $pull: {
        refreshTokens: {
          expiresAt: { $lt: new Date() },
        },
      },
    });

    await this.userModel.findByIdAndUpdate(userId, {
      $push: {
        refreshTokens: {
          token: hashedToken,
          createdAt: new Date(),
          expiresAt,
          deviceInfo: 'web',
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

    user.refreshTokens = user.refreshTokens.filter(
      (rt) => rt.expiresAt > new Date(),
    );

    const tokenIndex = await this.findTokenIndex(
      user.refreshTokens.map((rt) => rt.token),
      oldRefreshToken,
    );

    if (tokenIndex === -1) {
      user.refreshTokens = [];
      await user.save();
      throw new UnauthorizedException('Invalid Refresh Token');
    }

    user.refreshTokens.splice(tokenIndex, 1);

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

  // =================================================================
  // 4. READ OPERATIONS (Cached & Standard Mongoose)
  // =================================================================

  async findById(id: string): Promise<User> {
    const cacheKey = `user:${id}`;
    const cachedUser = await this.cacheManager.get<User>(cacheKey);
    if (cachedUser) {
      return cachedUser;
    }

    const user = await this.userModel
      .findById(id)
      .select('-password -refreshTokens')
      .exec();

    if (!user) throw new NotFoundException('User not found');
    await this.cacheManager.set(cacheKey, user, 30000);
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

    const maxLimit = Math.min(limit, 100);
    const query: any = {};

    if (search) {
      query.$text = { $search: search };
    }

    if (role) query.role = role;
    if (status) query.status = status;
    if (isEmailVerified !== undefined) query.isEmailVerified = isEmailVerified;

    const skip = (page - 1) * maxLimit;

    const [users, total] = await Promise.all([
      this.userModel
        .find(query)
        .skip(skip)
        .limit(maxLimit)
        .select('-password -refreshTokens')
        .exec(),
      this.userModel.countDocuments(query),
    ]);

    return {
      users,
      total,
      page,
      limit: maxLimit,
      totalPages: Math.ceil(total / maxLimit),
    };
  }

  async findByEmail(email: string): Promise<User> {
    const user = await this.userModel.findOne({ email }).select('+password');
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  // =================================================================
  // 5. WRITE OPERATIONS (With Cache Invalidation)
  // =================================================================

  async update(
    userId: string,
    updateUserInput: UpdateUserInput & {
      isEmailVerified?: boolean;
      status?: UserStatus;
    },
  ): Promise<User> {
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

    await this.cacheManager.del(`user:${userId}`);
    return user;
  }

  async delete(userId: string): Promise<User> {
    const user = await this.userModel.findByIdAndUpdate(
      userId,
      { isActive: false },
      { new: true },
    );
    if (!user) throw new NotFoundException('User not found');

    await this.cacheManager.del(`user:${userId}`);
    return user;
  }

  // =================================================================
  // 6. ADMIN ACTIONS WITH PERMISSION CHECKS
  // =================================================================

  /**
   * Check if admin has permission to modify target user
   * @param adminRole - Role of the admin performing the action
   * @param targetUserId - ID of the user being modified
   */
  private async checkAdminPermission(
    adminRole: UserRole,
    targetUserId: string,
  ): Promise<void> {
    const targetUser = await this.userModel.findById(targetUserId);
    if (!targetUser) throw new NotFoundException('Target user not found');

    // Super admins can modify anyone EXCEPT other super admins (unless promoting)
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

  async updateRole(
    updateRoleInput: UpdateUserRoleInput,
    adminRole?: UserRole,
  ): Promise<User> {
    // Check permissions if adminRole is provided
    if (adminRole) {
      await this.checkAdminPermission(adminRole, updateRoleInput.userId);

      // Regular admins cannot promote users to admin or super admin
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

      // Super admins CAN promote to super admin (this is the change)
      // But we'll handle it in a separate method with more security
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
      `User role updated: ${updateRoleInput.userId} -> ${updateRoleInput.role} by admin with role ${adminRole}`,
    );

    await this.cacheManager.del(`user:${updateRoleInput.userId}`);
    return user;
  }

  /**
   * Super Admin only - Promote user to Super Admin
   * This is a separate, more secure method with additional logging
   */
  async promoteToSuperAdmin(userId: string, promotedBy: string): Promise<User> {
    // Check if target user exists
    const targetUser = await this.userModel.findById(userId);
    if (!targetUser) {
      throw new NotFoundException('Target user not found');
    }

    // Cannot promote if already super admin
    if (targetUser.role === UserRole.SUPER_ADMIN) {
      throw new ConflictException('User is already a super admin');
    }

    // Promote to super admin
    const user = await this.userModel.findByIdAndUpdate(
      userId,
      {
        role: UserRole.SUPER_ADMIN,
        status: UserStatus.ACTIVE, // Ensure active status
      },
      { new: true },
    );

    if (!user) throw new NotFoundException('User not found');

    // Log this critical action
    this.logger.warn(
      `🚨 CRITICAL: User ${userId} (${user.email}) promoted to SUPER_ADMIN by ${promotedBy}`,
    );

    await this.cacheManager.del(`user:${userId}`);
    return user;
  }

  async updateStatus(
    updateStatusInput: UpdateUserStatusInput,
    adminRole?: UserRole,
  ): Promise<User> {
    // Check permissions if adminRole is provided
    if (adminRole) {
      await this.checkAdminPermission(adminRole, updateStatusInput.userId);
    }

    const user = await this.userModel.findByIdAndUpdate(
      updateStatusInput.userId,
      { status: updateStatusInput.status },
      { new: true },
    );
    if (!user) throw new NotFoundException('User not found');
    await this.cacheManager.del(`user:${updateStatusInput.userId}`);
    return user;
  }

  async banUser(
    banInput: BanUserInput,
    bannedBy: string,
    adminRole?: UserRole,
  ): Promise<User> {
    // Check permissions if adminRole is provided
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
      },
      { new: true },
    );
    if (!user) throw new NotFoundException('User not found');

    this.logger.warn(
      `User banned: ${banInput.userId} - Reason: ${banInput.reason} - By: ${bannedBy}`,
    );

    await this.cacheManager.del(`user:${banInput.userId}`);
    return user;
  }

  async unbanUser(userId: string, adminRole?: UserRole): Promise<User> {
    // Check permissions if adminRole is provided
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

    await this.cacheManager.del(`user:${userId}`);
    return user;
  }

  // =================================================================
  // 7. ADDRESS MANAGEMENT
  // =================================================================

  async addAddress(userId: string, addressInput: AddAddressInput) {
    const user = await this.userModel.findById(userId);
    if (!user) throw new NotFoundException('User not found');

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

    await this.cacheManager.del(`user:${userId}`);
    return updatedUser;
  }

  async updateAddress(
    userId: string,
    addressId: string,
    updateAddressInput: UpdateAddressInput,
  ): Promise<User> {
    if (updateAddressInput.address.isDefault) {
      await this.userModel.updateOne(
        { _id: userId },
        { $set: { 'addresses.$[].isDefault': false } },
      );
    }

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

    await this.cacheManager.del(`user:${userId}`);
    return user;
  }

  async deleteAddress(userId: string, addressId: string): Promise<User> {
    const user = await this.userModel.findByIdAndUpdate(
      userId,
      { $pull: { addresses: { _id: addressId } } },
      { new: true },
    );
    if (!user) throw new NotFoundException('User not found');
    await this.cacheManager.del(`user:${userId}`);
    return user;
  }

  async setDefaultAddress(userId: string, addressId: string): Promise<User> {
    await this.userModel.updateOne(
      { _id: userId },
      { $set: { 'addresses.$[].isDefault': false } },
    );
    const user = await this.userModel.findOneAndUpdate(
      { _id: userId, 'addresses._id': addressId },
      { $set: { 'addresses.$.isDefault': true } },
      { new: true },
    );
    if (!user) throw new NotFoundException('User or address not found');
    await this.cacheManager.del(`user:${userId}`);
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
    if (user.loginAttempts >= 4) {
      updates.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
    }
    await this.userModel.findByIdAndUpdate(user._id, updates);
  }

  async isAccountLocked(email: string): Promise<boolean> {
    const user = await this.userModel.findOne({ email });
    if (!user) return false;
    if (user.lockUntil && user.lockUntil > new Date()) return true;
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

  async updatePassword(userId: string, hashedPassword: string): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      password: hashedPassword,
      passwordResetToken: null,
      passwordResetExpires: null,
    });

    await this.cacheManager.del(`user:${userId}`);
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
    await this.cacheManager.del(`user:${userId}`);
  }

  async enableTwoFactor(userId: string): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      twoFactorEnabled: true,
      twoFactorEnabledAt: new Date(),
    });
    await this.cacheManager.del(`user:${userId}`);
  }

  async disableTwoFactor(userId: string): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      twoFactorEnabled: false,
      twoFactorSecret: null,
      twoFactorBackupCodes: [],
      twoFactorEnabledAt: null,
      twoFactorBackupCodesUsed: 0,
    });
    await this.cacheManager.del(`user:${userId}`);
  }

  async updateBackupCodes(
    userId: string,
    hashedCodes: string[],
  ): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      twoFactorBackupCodes: hashedCodes,
      twoFactorBackupCodesUsed: 0,
    });
    await this.cacheManager.del(`user:${userId}`);
  }

  async removeBackupCode(userId: string, index: number): Promise<void> {
    const user = await this.findByIdWithBackupCodes(userId);
    user.twoFactorBackupCodes.splice(index, 1);
    user.twoFactorBackupCodesUsed += 1;
    await user.save();
    await this.cacheManager.del(`user:${userId}`);
  }
}
