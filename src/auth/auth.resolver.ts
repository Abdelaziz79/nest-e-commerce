// src/auth/auth.resolver.ts
import { UseGuards } from '@nestjs/common';
import { Args, Mutation, Query, Resolver } from '@nestjs/graphql';
import { Throttle } from '@nestjs/throttler';
import { User } from '../users/schemas/user.schema';
import { AuthService } from './auth.service';
import { CurrentUser } from './decorators/current-user.decorator';
import { LoginInput, RefreshTokenInput, RegisterInput } from './dto/auth.input';
import { AuthPayload, UserInfo } from './dto/auth.types';
import { GqlAuthGuard } from './guards/gql-auth.guard';

@Resolver()
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}

  // STRICT: Limit to 5 attempts per minute to prevent brute-force
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Mutation(() => AuthPayload)
  async login(@Args('input') input: LoginInput) {
    return this.authService.login(input.email, input.password);
  }

  // STRICT: Limit to 5 creations per minute to prevent bot spam
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Mutation(() => AuthPayload)
  async register(@Args('input') input: RegisterInput) {
    return this.authService.register(input);
  }

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
