// src/auth/auth.resolver.ts - UPDATED LOGIN MUTATION

import { UseGuards } from '@nestjs/common';
import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import { Throttle } from '@nestjs/throttler';
import { User } from '../users/schemas/user.schema';
import { AuthService } from './auth.service';
import { CurrentUser } from './decorators/current-user.decorator';
import {
  Disable2FAInput,
  Enable2FAInput,
  Generate2FABackupCodesInput,
  LoginInput,
  RefreshTokenInput,
  RegisterInput,
  RequestPasswordResetInput,
  ResendOtpInput,
  ResetPasswordInput,
  Use2FABackupCodeInput,
  Verify2FALoginInput,
  Verify2FASetupInput,
  VerifyEmailInput,
} from './dto/auth.input';
import {
  AuthPayload,
  BackupCodesResponse,
  RegistrationResponse,
  TwoFactorSetupResponse,
  TwoFactorStatusResponse,
  UserInfo,
} from './dto/auth.types';
import { GqlAuthGuard } from './guards/gql-auth.guard';
import { TwoFactorService } from './services/two-factor.service';

@Resolver()
export class AuthResolver {
  constructor(
    private readonly authService: AuthService,
    private readonly twoFactorService: TwoFactorService,
  ) {}

  // ==========================================
  // LOGIN WITH DEVICE INFO
  // ==========================================

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Mutation(() => AuthPayload)
  async login(@Args('input') input: LoginInput, @Context() context: any) {
    // Extract device info from request
    const deviceInfo = {
      userAgent: context.req?.get('user-agent'),
      ip: context.req?.ip,
    };

    return this.authService.login(input.email, input.password, deviceInfo);
  }

  // ==========================================
  // REGISTER WITH EMAIL VERIFICATION
  // ==========================================

  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @Mutation(() => RegistrationResponse)
  async register(@Args('input') input: RegisterInput, @Context() context: any) {
    const ipAddress = context.req?.ip;
    const userAgent = context.req?.get('user-agent');

    return this.authService.register(input, { ipAddress, userAgent });
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Mutation(() => AuthPayload)
  async verifyEmail(@Args('input') input: VerifyEmailInput) {
    return this.authService.verifyEmail(input.email, input.otpCode);
  }

  // ==========================================
  // PASSWORD RESET WITH OTP
  // ==========================================

  @Throttle({ default: { limit: 3, ttl: 300000 } })
  @Mutation(() => Boolean)
  async requestPasswordReset(
    @Args('input') input: RequestPasswordResetInput,
    @Context() context: any,
  ) {
    const ipAddress = context.req?.ip;
    const userAgent = context.req?.get('user-agent');

    return this.authService.requestPasswordReset(input.email, {
      ipAddress,
      userAgent,
    });
  }

  @Throttle({ default: { limit: 5, ttl: 300000 } })
  @Mutation(() => Boolean)
  async resetPassword(@Args('input') input: ResetPasswordInput) {
    return this.authService.resetPasswordWithOtp(
      input.email,
      input.otpCode,
      input.newPassword,
    );
  }

  // ==========================================
  // RESEND OTP
  // ==========================================

  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @Mutation(() => Boolean)
  async resendOtp(
    @Args('input') input: ResendOtpInput,
    @Context() context: any,
  ) {
    const ipAddress = context.req?.ip;
    const userAgent = context.req?.get('user-agent');

    return this.authService.resendOtp(input.email, input.type, {
      ipAddress,
      userAgent,
    });
  }

  // ==========================================
  // TOKEN MANAGEMENT
  // ==========================================

  @Mutation(() => AuthPayload)
  async refreshToken(@Args('input') input: RefreshTokenInput) {
    return this.authService.refreshTokens(input.token);
  }

  @Mutation(() => Boolean)
  async logout(
    @Args('userId') userId: string,
    @Args('refreshToken') refreshToken: string,
  ) {
    return this.authService.logout(userId, refreshToken);
  }

  // ==========================================
  // AUTHENTICATED QUERIES
  // ==========================================

  @Query(() => UserInfo)
  @UseGuards(GqlAuthGuard)
  async whoAmI(@CurrentUser() user: User) {
    return {
      id: user._id?.toString() || user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
    };
  }

  // ==========================================
  // TWO-FACTOR AUTHENTICATION
  // ==========================================

  @Query(() => TwoFactorStatusResponse)
  @UseGuards(GqlAuthGuard)
  async twoFactorStatus(@CurrentUser() user: User) {
    return this.twoFactorService.getTwoFactorStatus(
      user._id?.toString() || user.id,
    );
  }

  @Mutation(() => TwoFactorSetupResponse)
  @UseGuards(GqlAuthGuard)
  async initiate2FASetup(
    @CurrentUser() user: User,
    @Args('input') input: Enable2FAInput,
  ) {
    return this.twoFactorService.initiate2FASetup(
      user._id?.toString() || user.id,
      user.email,
      input.password,
    );
  }

  @Mutation(() => Boolean)
  @UseGuards(GqlAuthGuard)
  async verify2FASetup(
    @CurrentUser() user: User,
    @Args('input') input: Verify2FASetupInput,
  ) {
    return this.twoFactorService.verifyAndEnableTwoFactor(
      user._id?.toString() || user.id,
      input.token,
    );
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Mutation(() => AuthPayload)
  async verify2FALogin(@Args('input') input: Verify2FALoginInput) {
    return this.twoFactorService.verify2FALogin(
      input.email,
      input.token,
      input.tempToken,
    );
  }

  @Mutation(() => Boolean)
  @UseGuards(GqlAuthGuard)
  async disable2FA(
    @CurrentUser() user: User,
    @Args('input') input: Disable2FAInput,
  ) {
    return this.twoFactorService.disable2FA(
      user._id?.toString() || user.id,
      user.email,
      input.password,
      input.token,
    );
  }

  @Mutation(() => BackupCodesResponse)
  @UseGuards(GqlAuthGuard)
  async generate2FABackupCodes(
    @CurrentUser() user: User,
    @Args('input') input: Generate2FABackupCodesInput,
  ) {
    return this.twoFactorService.generateBackupCodesWithVerification(
      user._id?.toString() || user.id,
      user.email,
      input.password,
    );
  }

  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @Mutation(() => AuthPayload)
  async use2FABackupCode(@Args('input') input: Use2FABackupCodeInput) {
    return this.twoFactorService.use2FABackupCode(
      input.email,
      input.backupCode,
      input.tempToken,
    );
  }
}
