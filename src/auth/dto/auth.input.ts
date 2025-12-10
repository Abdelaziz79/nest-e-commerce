// src/auth/dto/auth.input.ts
import { Field, InputType, registerEnumType } from '@nestjs/graphql';
import {
  IsEmail,
  IsEnum,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';
import { OtpType } from '../schemas/otp.schema';

// Register OtpType enum for GraphQL
registerEnumType(OtpType, {
  name: 'OtpType',
  description: 'Types of OTP verification',
});

@InputType()
export class LoginInput {
  @Field()
  @IsEmail()
  email: string;

  @Field()
  @IsString()
  password: string;
}

@InputType()
export class RegisterInput {
  @Field()
  @IsString()
  firstName: string;

  @Field()
  @IsString()
  lastName: string;

  @Field()
  @IsEmail()
  email: string;

  @Field()
  @IsString()
  @MinLength(8)
  password: string;
}

@InputType()
export class VerifyEmailInput {
  @Field()
  @IsEmail()
  email: string;

  @Field()
  @IsString()
  @MinLength(6)
  otpCode: string;
}

@InputType()
export class RefreshTokenInput {
  @Field()
  @IsString()
  token: string;
}

@InputType()
export class RequestPasswordResetInput {
  @Field()
  @IsEmail()
  email: string;
}

@InputType()
export class ResetPasswordInput {
  @Field()
  @IsEmail()
  email: string;

  @Field()
  @IsString()
  @MinLength(6)
  otpCode: string;

  @Field()
  @IsString()
  @MinLength(8)
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message:
      'Password must contain uppercase, lowercase, and number/special character',
  })
  newPassword: string;
}

@InputType()
export class ResendOtpInput {
  @Field()
  @IsEmail()
  email: string;

  @Field(() => OtpType)
  @IsEnum(OtpType)
  type: OtpType;
}

@InputType()
export class Enable2FAInput {
  @Field()
  @IsString()
  password: string; // User must confirm with password
}

@InputType()
export class Verify2FASetupInput {
  @Field()
  @IsString()
  @MinLength(6)
  @MaxLength(6)
  token: string; // 6-digit code from authenticator app
}

@InputType()
export class Disable2FAInput {
  @Field()
  @IsString()
  password: string;

  @Field()
  @IsString()
  @MinLength(6)
  @MaxLength(6)
  token: string; // 6-digit code to confirm
}

@InputType()
export class Verify2FALoginInput {
  @Field()
  @IsEmail()
  email: string;

  @Field()
  @IsString()
  @MinLength(6)
  @MaxLength(6)
  token: string;

  @Field()
  @IsString()
  tempToken: string; // Temporary token from initial login
}

@InputType()
export class Generate2FABackupCodesInput {
  @Field()
  @IsString()
  password: string;
}

@InputType()
export class Use2FABackupCodeInput {
  @Field()
  @IsEmail()
  email: string;

  @Field()
  @IsString()
  backupCode: string;

  @Field()
  @IsString()
  tempToken: string;
}
