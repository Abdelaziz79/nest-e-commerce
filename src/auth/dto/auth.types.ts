// src/auth/dto/auth.types.ts
import { Field, ObjectType } from '@nestjs/graphql';

@ObjectType()
export class UserInfo {
  @Field()
  id: string;

  @Field()
  email: string;

  @Field()
  firstName: string;

  @Field()
  lastName: string;

  @Field()
  role: string;
}

@ObjectType()
export class AuthPayload {
  @Field({ nullable: true })
  accessToken?: string;

  @Field({ nullable: true })
  refreshToken?: string;

  @Field(() => UserInfo, { nullable: true })
  user?: UserInfo;

  // 2FA fields
  @Field({ defaultValue: false })
  requiresTwoFactor: boolean;

  @Field({ nullable: true })
  tempToken?: string;

  @Field({ nullable: true })
  message?: string;
}

@ObjectType()
export class RegistrationResponse {
  @Field()
  success: boolean;

  @Field()
  message: string;

  @Field()
  email: string;
}

@ObjectType()
export class TwoFactorSetupResponse {
  @Field()
  secret: string; // Base32 encoded secret (show once)

  @Field()
  qrCode: string; // Data URL for QR code image

  @Field()
  manualEntryKey: string; // For manual entry in authenticator app

  @Field()
  message: string;
}

@ObjectType()
export class TwoFactorStatusResponse {
  @Field()
  enabled: boolean;

  @Field({ nullable: true })
  enabledAt?: Date;

  @Field()
  hasBackupCodes: boolean;

  @Field()
  backupCodesRemaining: number;
}

@ObjectType()
export class BackupCodesResponse {
  @Field(() => [String])
  codes: string[];

  @Field()
  message: string;
}

@ObjectType()
export class TwoFactorAuthPayload {
  @Field()
  requiresTwoFactor: boolean;

  @Field({ nullable: true })
  tempToken?: string; // Temporary token for 2FA verification

  @Field({ nullable: true })
  accessToken?: string;

  @Field({ nullable: true })
  refreshToken?: string;

  @Field(() => UserInfo, { nullable: true })
  user?: UserInfo;
}
