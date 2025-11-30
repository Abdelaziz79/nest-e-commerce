// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { User } from '../users/schemas/user.schema';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  // Generate JWT token
  async generateToken(user: User) {
    const payload = {
      sub: user._id.toString(),
      email: user.email,
      role: user.role,
    };

    return {
      accessToken: this.jwtService.sign(payload),
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      },
    };
  }

  // Login
  async login(email: string, password: string) {
    // Check if account is locked
    const isLocked = await this.usersService.isAccountLocked(email);
    if (isLocked) {
      throw new UnauthorizedException(
        'Account is temporarily locked due to too many failed login attempts',
      );
    }

    // Find user
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      await this.usersService.incrementLoginAttempts(email);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if account is active
    if (!user.isActive) {
      throw new UnauthorizedException('Account is deactivated');
    }

    // Check if account is banned
    if (user.status === 'banned') {
      throw new UnauthorizedException(
        `Account is banned. Reason: ${user.banReason}`,
      );
    }

    // Verify password
    const isPasswordValid = await this.usersService.verifyPassword(
      password,
      user.password,
    );

    if (!isPasswordValid) {
      await this.usersService.incrementLoginAttempts(email);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Update last login
    await this.usersService.updateLastLogin(user._id.toString());

    return this.generateToken(user);
  }

  // Register
  async register(createUserInput: any) {
    return this.usersService.create(createUserInput);
  }

  // Generate email verification token
  generateVerificationToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  // Generate password reset token
  generatePasswordResetToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }
}
