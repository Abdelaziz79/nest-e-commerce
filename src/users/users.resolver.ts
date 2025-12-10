import { UseGuards } from '@nestjs/common';
import { Args, ID, Mutation, Query, Resolver } from '@nestjs/graphql';
import { SkipThrottle, Throttle } from '@nestjs/throttler';
import { AuditLog } from 'src/common/decorators/audit-log.decorator';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { Roles } from '../auth/decorators/roles.decorator';
import { GqlAuthGuard } from '../auth/guards/gql-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
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
import {
  PaginatedUsersType,
  UserAdminType,
  UserProfileType,
  UserType,
} from './dto/user.types';
import { User } from './schemas/user.schema';
import { UsersService } from './users.service';

@Resolver(() => UserType)
export class UsersResolver {
  constructor(private readonly usersService: UsersService) {}

  // ==========================================
  // Public Queries
  // ==========================================

  @Query(() => UserType, { name: 'user' })
  async getUser(@Args('id', { type: () => ID }) id: string) {
    return this.usersService.findById(id);
  }

  // ==========================================
  // Protected Queries
  // ==========================================

  @Query(() => UserProfileType, { name: 'me' })
  @UseGuards(GqlAuthGuard)
  async getMe(@CurrentUser() user: User) {
    return this.usersService.findById(user._id.toString());
  }

  // ==========================================
  // Admin Queries (Skip Throttling)
  // ==========================================

  @SkipThrottle()
  @Query(() => PaginatedUsersType, { name: 'users' })
  @UseGuards(GqlAuthGuard, RolesGuard)
  @Roles('admin', 'super_admin')
  async getAllUsers(
    @Args('filters', { nullable: true }) filters?: UsersFilterInput,
  ) {
    return this.usersService.findAll(filters);
  }

  @SkipThrottle()
  @Query(() => UserAdminType, { name: 'userAdmin' })
  @UseGuards(GqlAuthGuard, RolesGuard)
  @Roles('admin', 'super_admin')
  async getUserAdmin(@Args('id', { type: () => ID }) id: string) {
    return this.usersService.findById(id);
  }

  // ==========================================
  // Public Mutations (Strict Throttling)
  // ==========================================

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Mutation(() => UserProfileType)
  async createUser(@Args('input') input: CreateUserInput) {
    return this.usersService.create(input);
  }

  // ==========================================
  // Protected Mutations
  // ==========================================

  @Mutation(() => UserProfileType)
  @UseGuards(GqlAuthGuard)
  async updateUser(
    @CurrentUser() user: User,
    @Args('input') input: UpdateUserInput,
  ) {
    return this.usersService.update(user._id.toString(), input);
  }

  @Mutation(() => UserProfileType)
  @UseGuards(GqlAuthGuard)
  async addAddress(
    @CurrentUser() user: User,
    @Args('input') input: AddAddressInput,
  ) {
    return this.usersService.addAddress(user._id.toString(), input);
  }

  @Mutation(() => UserProfileType)
  @UseGuards(GqlAuthGuard)
  async updateAddress(
    @CurrentUser() user: User,
    @Args('addressId', { type: () => ID }) addressId: string,
    @Args('input') input: UpdateAddressInput,
  ) {
    return this.usersService.updateAddress(
      user._id.toString(),
      addressId,
      input,
    );
  }

  @Mutation(() => UserProfileType)
  @UseGuards(GqlAuthGuard)
  async deleteAddress(
    @CurrentUser() user: User,
    @Args('addressId', { type: () => ID }) addressId: string,
  ) {
    return this.usersService.deleteAddress(user._id.toString(), addressId);
  }

  @Mutation(() => UserProfileType)
  @UseGuards(GqlAuthGuard)
  async setDefaultAddress(
    @CurrentUser() user: User,
    @Args('addressId', { type: () => ID }) addressId: string,
  ) {
    return this.usersService.setDefaultAddress(user._id.toString(), addressId);
  }

  @Mutation(() => UserProfileType)
  @UseGuards(GqlAuthGuard)
  async deleteUser(@CurrentUser() user: User) {
    return this.usersService.delete(user._id.toString());
  }

  // ==========================================
  // Admin Mutations (Skip Throttling)
  // ==========================================

  @SkipThrottle()
  @Mutation(() => UserAdminType)
  @UseGuards(GqlAuthGuard, RolesGuard)
  @Roles('admin', 'super_admin')
  @AuditLog('update_user_role')
  async updateUserRole(
    @CurrentUser() admin: User,
    @Args('input') input: UpdateUserRoleInput,
  ) {
    return this.usersService.updateRole(input, admin.role);
  }

  @SkipThrottle()
  @Mutation(() => UserAdminType)
  @UseGuards(GqlAuthGuard, RolesGuard)
  @Roles('admin', 'super_admin')
  @AuditLog('update_user_status')
  async updateUserStatus(
    @CurrentUser() admin: User,
    @Args('input') input: UpdateUserStatusInput,
  ) {
    return this.usersService.updateStatus(input, admin.role);
  }

  @SkipThrottle()
  @Mutation(() => UserAdminType)
  @UseGuards(GqlAuthGuard, RolesGuard)
  @Roles('admin', 'super_admin')
  @AuditLog('ban_user')
  async banUser(
    @CurrentUser() admin: User,
    @Args('input') input: BanUserInput,
  ) {
    return this.usersService.banUser(input, admin._id.toString(), admin.role);
  }

  @SkipThrottle()
  @Mutation(() => UserAdminType)
  @UseGuards(GqlAuthGuard, RolesGuard)
  @Roles('admin', 'super_admin')
  @AuditLog('unban_user')
  async unbanUser(
    @CurrentUser() admin: User,
    @Args('userId', { type: () => ID }) userId: string,
  ) {
    return this.usersService.unbanUser(userId, admin.role);
  }

  // ==========================================
  // Super Admin Only - Promote to Super Admin
  // ==========================================

  @SkipThrottle()
  @Mutation(() => UserAdminType)
  @UseGuards(GqlAuthGuard, RolesGuard)
  @Roles('super_admin')
  @AuditLog('promote_to_super_admin')
  async promoteToSuperAdmin(
    @CurrentUser() admin: User,
    @Args('userId', { type: () => ID }) userId: string,
  ) {
    return this.usersService.promoteToSuperAdmin(userId, admin._id.toString());
  }
}
