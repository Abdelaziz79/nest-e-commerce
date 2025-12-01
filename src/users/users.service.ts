// src/users/users.service.ts
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import {
  ConflictException,
  Inject,
  Injectable,
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
import { User, UserStatus } from './schemas/user.schema';

@Injectable()
export class UsersService {
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
  // 2. TOKEN MANAGEMENT (Encapsulated)
  // =================================================================

  async addRefreshToken(userId: string, refreshToken: string): Promise<void> {
    const hashedToken = await bcrypt.hash(refreshToken, 10);
    await this.userModel.findByIdAndUpdate(userId, {
      $push: { refreshTokens: hashedToken },
    });
  }

  async rotateRefreshToken(
    userId: string,
    oldRefreshToken: string,
    newRefreshToken: string,
  ): Promise<User> {
    const user = await this.userModel.findById(userId).select('+refreshTokens');
    if (!user) throw new UnauthorizedException('User not found');

    const tokenIndex = await this.findTokenIndex(
      user.refreshTokens,
      oldRefreshToken,
    );

    if (tokenIndex === -1) {
      // Security: Reuse detection could trigger a wipe of all tokens here
      throw new UnauthorizedException('Invalid Refresh Token');
    }

    // Remove old
    user.refreshTokens.splice(tokenIndex, 1);

    // Add new
    const hashedNewToken = await bcrypt.hash(newRefreshToken, 10);
    user.refreshTokens.push(hashedNewToken);

    return user.save();
  }

  async revokeRefreshToken(
    userId: string,
    refreshToken: string,
  ): Promise<void> {
    const user = await this.userModel.findById(userId).select('+refreshTokens');
    if (!user) return;

    const tokenIndex = await this.findTokenIndex(
      user.refreshTokens,
      refreshToken,
    );

    if (tokenIndex !== -1) {
      user.refreshTokens.splice(tokenIndex, 1);
      await user.save();
    }
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
  // 3. READ OPERATIONS
  // =================================================================

  // Cached
  async findById(id: string): Promise<User> {
    const cacheKey = `user:${id}`;

    // 1. Try Cache
    const cachedUser = await this.cacheManager.get<User>(cacheKey);
    if (cachedUser) {
      console.log('Cache hit');
      return cachedUser;
    }

    // 2. Try DB
    const user = await this.userModel.findById(id);
    if (!user) throw new NotFoundException('User not found');

    // 3. Save to Cache (60s TTL)
    console.log('Cache miss. Caching user with key:', cacheKey);
    await this.cacheManager.set(cacheKey, user, 60000);

    return user;
  }

  // NOTE: We generally do NOT cache list/search results because
  // invalidating specific pages when a single user updates is complex
  // and inefficient.
  async findAll(filters?: UsersFilterInput) {
    const {
      search,
      role,
      status,
      isEmailVerified,
      page = 1,
      limit = 10,
    } = filters || {};
    const query: any = {};

    if (search) {
      query.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { username: { $regex: search, $options: 'i' } },
      ];
    }

    if (role) query.role = role;
    if (status) query.status = status;
    if (isEmailVerified !== undefined) query.isEmailVerified = isEmailVerified;

    const skip = (page - 1) * limit;

    const [users, total] = await Promise.all([
      this.userModel.find(query).skip(skip).limit(limit).exec(),
      this.userModel.countDocuments(query),
    ]);

    return {
      users,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  // NOTE: Never cache findByEmail as it returns sensitive password fields
  // and is used for authentication logic requiring Mongoose Documents
  async findByEmail(email: string): Promise<User> {
    const user = await this.userModel.findOne({ email }).select('+password');
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  // =================================================================
  // 4. WRITE OPERATIONS (With Cache Invalidation)
  // =================================================================

  async update(
    userId: string,
    updateUserInput: UpdateUserInput,
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

    // Invalidate Cache
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

    // Invalidate Cache
    await this.cacheManager.del(`user:${userId}`);

    return user;
  }

  // =================================================================
  // 5. ADMIN ACTIONS (With Cache Invalidation)
  // =================================================================

  async updateRole(updateRoleInput: UpdateUserRoleInput): Promise<User> {
    const user = await this.userModel.findByIdAndUpdate(
      updateRoleInput.userId,
      { role: updateRoleInput.role },
      { new: true },
    );
    if (!user) throw new NotFoundException('User not found');

    // Invalidate Cache
    await this.cacheManager.del(`user:${updateRoleInput.userId}`);

    return user;
  }

  async updateStatus(updateStatusInput: UpdateUserStatusInput): Promise<User> {
    const user = await this.userModel.findByIdAndUpdate(
      updateStatusInput.userId,
      { status: updateStatusInput.status },
      { new: true },
    );
    if (!user) throw new NotFoundException('User not found');

    // Invalidate Cache
    await this.cacheManager.del(`user:${updateStatusInput.userId}`);

    return user;
  }

  async banUser(banInput: BanUserInput, bannedBy: string): Promise<User> {
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

    // Invalidate Cache
    await this.cacheManager.del(`user:${banInput.userId}`);

    return user;
  }

  async unbanUser(userId: string): Promise<User> {
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

    // Invalidate Cache
    await this.cacheManager.del(`user:${userId}`);

    return user;
  }

  // =================================================================
  // 6. ADDRESS MANAGEMENT (Atomic & Cached)
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

    // Invalidate Cache
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

    // Invalidate Cache
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

    // Invalidate Cache
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

    // Invalidate Cache
    await this.cacheManager.del(`user:${userId}`);

    return user;
  }

  // =================================================================
  // 7. LOGIN HELPERS
  // =================================================================

  async updateLastLogin(userId: string): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      lastLogin: new Date(),
      loginAttempts: 0,
    });
    // Optional: Invalidate cache if you want 'lastLogin' to update instantly on the UI
    // await this.cacheManager.del(`user:${userId}`);
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
}
