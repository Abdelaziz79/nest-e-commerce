// src/users/dto/user.input.ts
import { Field, InputType } from '@nestjs/graphql';
import { Type } from 'class-transformer';
import {
  IsBoolean,
  IsDate,
  IsDateString,
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsPhoneNumber,
  IsString,
  IsUrl,
  Matches,
  MaxLength,
  MinLength,
  ValidateNested,
} from 'class-validator';
import { UserRole, UserStatus } from '../schemas/user.schema';

@InputType()
export class CoordinatesInput {
  @Field()
  @IsOptional()
  lat: number;

  @Field()
  @IsOptional()
  lng: number;
}

@InputType()
export class AddressInput {
  @Field()
  @IsString()
  address: string;

  @Field()
  @IsString()
  city: string;

  @Field()
  @IsString()
  country: string;

  @Field()
  @IsString()
  postalCode: string;

  @Field()
  @IsString()
  phoneNumber: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  isDefault?: boolean;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  label?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  recipientName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  recipientPhone?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  instructions?: string;

  @Field(() => CoordinatesInput, { nullable: true })
  @IsOptional()
  @ValidateNested()
  @Type(() => CoordinatesInput)
  coordinates?: CoordinatesInput;
}

@InputType()
export class CreateUserInput {
  @Field()
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  @MaxLength(50)
  @Matches(/^[a-zA-Z\s'-]+$/, {
    message:
      'First name can only contain letters, spaces, hyphens and apostrophes',
  })
  firstName: string;

  @Field()
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  @MaxLength(50)
  @Matches(/^[a-zA-Z\s'-]+$/, {
    message:
      'Last name can only contain letters, spaces, hyphens and apostrophes',
  })
  lastName: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MinLength(3)
  @MaxLength(30)
  @Matches(/^[a-zA-Z0-9_-]+$/, {
    message:
      'Username can only contain letters, numbers, underscores and hyphens',
  })
  username?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  displayName?: string;

  @Field()
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @MaxLength(255)
  email: string;

  @Field()
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(128, { message: 'Password is too long' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, one number and one special character (@$!%*?&)',
  })
  password: string;

  @Field(() => UserRole, { nullable: true })
  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;

  @Field({ nullable: true })
  @IsOptional()
  @IsPhoneNumber(undefined, { message: 'Please provide a valid phone number' })
  phone?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsUrl({}, { message: 'Please provide a valid URL for avatar' })
  @MaxLength(500)
  avatar?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(10)
  @Matches(/^[a-z]{2}$/, {
    message: 'Language code must be 2 lowercase letters',
  })
  preferredLanguage?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(3)
  @Matches(/^[A-Z]{3}$/, {
    message: 'Currency code must be 3 uppercase letters',
  })
  preferredCurrency?: string;

  @Field({ nullable: true })
  @IsOptional()
  @Type(() => Date)
  @IsDate()
  dateOfBirth?: Date;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @IsEnum(['male', 'female', 'other', 'prefer_not_to_say'])
  gender?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  newsletter?: boolean;
}

@InputType()
export class UpdateUserInput {
  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  firstName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  lastName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  username?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  displayName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  phone?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  avatar?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  preferredLanguage?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  preferredCurrency?: string;

  @Field({ nullable: true })
  @IsOptional()
  @Type(() => Date)
  @IsDate()
  dateOfBirth?: Date;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  gender?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  newsletter?: boolean;
}

@InputType()
export class UpdateUserRoleInput {
  @Field()
  @IsString()
  userId: string;

  @Field(() => UserRole)
  @IsEnum(UserRole)
  role: UserRole;
}

@InputType()
export class BanUserInput {
  @Field()
  @IsString()
  userId: string;

  @Field()
  @IsString()
  reason: string;
}

@InputType()
export class UpdateUserStatusInput {
  @Field()
  @IsString()
  userId: string;

  @Field(() => UserStatus)
  @IsEnum(UserStatus)
  status: UserStatus;
}

@InputType()
export class AddAddressInput {
  @Field(() => AddressInput)
  @ValidateNested()
  @Type(() => AddressInput)
  address: AddressInput;
}

@InputType()
export class UpdateAddressInput {
  @Field()
  @IsString()
  addressId: string;

  @Field(() => AddressInput)
  @ValidateNested()
  @Type(() => AddressInput)
  address: AddressInput;
}

@InputType()
export class UsersFilterInput {
  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  search?: string;

  @Field(() => UserRole, { nullable: true })
  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;

  @Field(() => UserStatus, { nullable: true })
  @IsOptional()
  @IsEnum(UserStatus)
  status?: UserStatus;

  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  isEmailVerified?: boolean;

  @Field({ nullable: true })
  @IsOptional()
  page?: number;

  @Field({ nullable: true })
  @IsOptional()
  limit?: number;
}

@InputType()
export class InternalCreateUserInput extends CreateUserInput {
  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  isEmailVerified?: boolean;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  googleId?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  githubId?: string;
}
