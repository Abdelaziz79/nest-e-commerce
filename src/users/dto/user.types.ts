// src/users/dto/user.types.ts
import { Field, ID, ObjectType, registerEnumType } from '@nestjs/graphql';
import { UserRole, UserStatus } from '../schemas/user.schema';

// Register enums for GraphQL
registerEnumType(UserRole, {
  name: 'UserRole',
});

registerEnumType(UserStatus, {
  name: 'UserStatus',
});

@ObjectType()
export class AddressType {
  @Field(() => ID)
  _id: string;

  @Field()
  address: string;

  @Field()
  city: string;

  @Field()
  country: string;

  @Field()
  postalCode: string;

  @Field()
  phoneNumber: string;

  @Field()
  isDefault: boolean;

  @Field({ nullable: true })
  label?: string;

  @Field({ nullable: true })
  recipientName?: string;

  @Field({ nullable: true })
  recipientPhone?: string;

  @Field({ nullable: true })
  instructions?: string;

  @Field(() => CoordinatesType, { nullable: true })
  coordinates?: CoordinatesType;

  @Field()
  createdAt: Date;

  @Field()
  updatedAt: Date;
}

@ObjectType()
export class CoordinatesType {
  @Field()
  lat: number;

  @Field()
  lng: number;
}

// Public User Type (for other users to see)
@ObjectType()
export class UserType {
  @Field(() => ID)
  _id: string;

  @Field()
  firstName: string;

  @Field()
  lastName: string;

  @Field()
  fullName: string;

  @Field({ nullable: true })
  username?: string;

  @Field({ nullable: true })
  displayName?: string;

  @Field({ nullable: true })
  avatar?: string;

  @Field(() => UserRole)
  role: UserRole;

  @Field()
  createdAt: Date;

  @Field()
  updatedAt: Date;
}

// User Profile Type (for the user themselves)
@ObjectType()
export class UserProfileType {
  @Field(() => ID)
  _id: string;

  @Field()
  firstName: string;

  @Field()
  lastName: string;

  @Field()
  fullName: string;

  @Field({ nullable: true })
  username?: string;

  @Field({ nullable: true })
  displayName?: string;

  @Field()
  email: string;

  @Field(() => UserRole)
  role: UserRole;

  @Field(() => UserStatus)
  status: UserStatus;

  @Field({ nullable: true })
  avatar?: string;

  @Field(() => [AddressType])
  addresses: AddressType[];

  @Field()
  isEmailVerified: boolean;

  @Field({ nullable: true })
  phone?: string;

  @Field()
  phoneVerified: boolean;

  @Field({ nullable: true })
  lastLogin?: Date;

  @Field()
  isActive: boolean;

  @Field()
  preferredLanguage: string;

  @Field()
  preferredCurrency: string;

  @Field({ nullable: true })
  dateOfBirth?: Date;

  @Field({ nullable: true })
  gender?: string;

  @Field()
  twoFactorEnabled: boolean;

  @Field()
  newsletter: boolean;

  @Field({ nullable: true })
  termsAcceptedAt?: Date;

  @Field({ nullable: true })
  privacyPolicyAcceptedAt?: Date;

  @Field()
  createdAt: Date;

  @Field()
  updatedAt: Date;
}

// Admin User Type (for admins/super admins)
@ObjectType()
export class UserAdminType extends UserProfileType {
  @Field({ nullable: true })
  banReason?: string;

  @Field({ nullable: true })
  bannedAt?: Date;

  @Field({ nullable: true })
  bannedBy?: string;

  @Field()
  loginAttempts: number;

  @Field({ nullable: true })
  lockUntil?: Date;
}

// Paginated Users Response
@ObjectType()
export class PaginatedUsersType {
  @Field(() => [UserAdminType])
  users: UserAdminType[];

  @Field()
  total: number;

  @Field()
  page: number;

  @Field()
  limit: number;

  @Field()
  totalPages: number;
}
