// src/users/users.service.ts
import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { Model } from 'mongoose';
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
  ) {}

  // Create a new user
  async create(createUserInput: CreateUserInput): Promise<User> {
    // Check if email already exists
    const existingUser = await this.userModel.findOne({
      email: createUserInput.email,
    });
    if (existingUser) {
      throw new ConflictException('Email already exists');
    }

    // Check if username exists (if provided)
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

    const user = new this.userModel({
      ...createUserInput,
      password: hashedPassword,
    });

    return user.save();
  }

  // Find all users with filters and pagination
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

  // Find user by ID
  async findById(id: string): Promise<User> {
    const user = await this.userModel.findById(id);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  // Find user by email
  async findByEmail(email: string): Promise<User> {
    const user = await this.userModel.findOne({ email }).select('+password');
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  // Update user profile
  async update(
    userId: string,
    updateUserInput: UpdateUserInput,
  ): Promise<User> {
    // Check if username is being updated and if it's already taken
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

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  // Update user role (Admin only)
  async updateRole(updateRoleInput: UpdateUserRoleInput): Promise<User> {
    const user = await this.userModel.findByIdAndUpdate(
      updateRoleInput.userId,
      { role: updateRoleInput.role },
      { new: true },
    );

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  // Update user status (Admin only)
  async updateStatus(updateStatusInput: UpdateUserStatusInput): Promise<User> {
    const user = await this.userModel.findByIdAndUpdate(
      updateStatusInput.userId,
      { status: updateStatusInput.status },
      { new: true },
    );

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  // Ban user (Admin only)
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

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  // Unban user (Admin only)
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

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  // Add address
  async addAddress(
    userId: string,
    addressInput: AddAddressInput,
  ): Promise<User> {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // If this is set as default, unset other defaults
    if (addressInput.address.isDefault) {
      user.addresses.forEach((addr) => {
        addr.isDefault = false;
      });
    }

    user.addresses.push(addressInput.address as any);
    return user.save();
  }

  // Update address
  async updateAddress(
    userId: string,
    addressId: string,
    updateAddressInput: UpdateAddressInput,
  ): Promise<User> {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const addressIndex = user.addresses.findIndex(
      (addr) => addr._id.toString() === addressId,
    );

    if (addressIndex === -1) {
      throw new NotFoundException('Address not found');
    }

    // If this is set as default, unset other defaults
    if (updateAddressInput.address.isDefault) {
      user.addresses.forEach((addr, index) => {
        if (index !== addressIndex) {
          addr.isDefault = false;
        }
      });
    }

    user.addresses[addressIndex] = {
      ...user.addresses[addressIndex],
      ...updateAddressInput.address,
    } as any;

    return user.save();
  }

  // Delete address
  async deleteAddress(userId: string, addressId: string): Promise<User> {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    user.addresses = user.addresses.filter(
      (addr) => addr._id.toString() !== addressId,
    );

    return user.save();
  }

  // Set default address
  async setDefaultAddress(userId: string, addressId: string): Promise<User> {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    user.addresses.forEach((addr) => {
      addr.isDefault = addr._id.toString() === addressId;
    });

    return user.save();
  }

  // Delete user (soft delete)
  async delete(userId: string): Promise<User> {
    const user = await this.userModel.findByIdAndUpdate(
      userId,
      { isActive: false },
      { new: true },
    );

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  // Verify password
  async verifyPassword(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }

  // Update last login
  async updateLastLogin(userId: string): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      lastLogin: new Date(),
      loginAttempts: 0,
    });
  }

  // Increment login attempts
  async incrementLoginAttempts(email: string): Promise<void> {
    const user = await this.userModel.findOne({ email });
    if (!user) return;

    const updates: any = { $inc: { loginAttempts: 1 } };

    // Lock account after 5 failed attempts for 15 minutes
    if (user.loginAttempts >= 4) {
      updates.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
    }

    await this.userModel.findByIdAndUpdate(user._id, updates);
  }

  // Check if account is locked
  async isAccountLocked(email: string): Promise<boolean> {
    const user = await this.userModel.findOne({ email });
    if (!user) return false;

    if (user.lockUntil && user.lockUntil > new Date()) {
      return true;
    }

    // Unlock account if lock time has passed
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
