// src/auth/auth.resolver.ts
import { UseGuards } from '@nestjs/common';
import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import { Throttle } from '@nestjs/throttler';
import { User } from '../users/schemas/user.schema';
import { AuthService } from './auth.service';
import { CurrentUser } from './decorators/current-user.decorator';
import {
  LoginInput,
  RefreshTokenInput,
  RegisterInput,
  RequestPasswordResetInput,
  ResendOtpInput,
  ResetPasswordInput,
  VerifyEmailInput,
} from './dto/auth.input';
import { AuthPayload, RegistrationResponse, UserInfo } from './dto/auth.types';
import { GqlAuthGuard } from './guards/gql-auth.guard';

@Resolver()
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}

  // ==========================================
  // SIMPLE LOGIN (EMAIL + PASSWORD)
  // ==========================================

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Mutation(() => AuthPayload)
  async login(@Args('input') input: LoginInput) {
    return this.authService.login(input.email, input.password);
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
      id: user._id.toString(),
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
    };
  }
}
