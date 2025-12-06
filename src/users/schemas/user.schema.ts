// src/users/schemas/user.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { Document } from 'mongoose';

export enum UserRole {
  CUSTOMER = 'customer',
  ADMIN = 'admin',
  SUPER_ADMIN = 'super_admin',
  VENDOR = 'vendor',
  MODERATOR = 'moderator',
  SUPPORT = 'support',
}

export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  BANNED = 'banned',
  PENDING = 'pending',
  SUSPENDED = 'suspended',
}

export interface RefreshTokenDocument {
  token: string; // hashed
  createdAt: Date;
  expiresAt: Date;
  deviceInfo?: string;
}

@Schema()
export class Address {
  _id: string;

  @Prop({ required: true })
  address: string;

  @Prop({ required: true })
  city: string;

  @Prop({ required: true })
  country: string;

  @Prop({ required: true })
  postalCode: string;

  @Prop({ required: true })
  phoneNumber: string;

  @Prop({ default: false })
  isDefault: boolean;

  @Prop()
  label: string;

  @Prop()
  recipientName: string;

  @Prop()
  recipientPhone: string;

  @Prop()
  instructions: string;

  @Prop({ type: { lat: Number, lng: Number } })
  coordinates: {
    lat: number;
    lng: number;
  };

  @Prop({ default: Date.now })
  createdAt: Date;

  @Prop({ default: Date.now })
  updatedAt: Date;
}

export const AddressSchema = SchemaFactory.createForClass(Address);

@Schema({ timestamps: true })
export class User extends Document {
  @Prop({ required: true, trim: true })
  firstName: string;

  @Prop({ required: true, trim: true })
  lastName: string;

  @Prop({ trim: true, lowercase: true })
  username: string;

  @Prop()
  displayName: string;

  @Prop({ required: true, lowercase: true, trim: true })
  email: string;

  @Prop()
  googleId: string;

  @Prop()
  githubId: string;

  @Prop({ required: true, select: false })
  password: string;

  @Prop({ type: String, enum: UserRole, default: UserRole.CUSTOMER })
  role: UserRole;

  @Prop({ type: String, enum: UserStatus, default: UserStatus.PENDING })
  status: UserStatus;

  @Prop()
  banReason: string;

  @Prop()
  bannedAt: Date;

  @Prop({ type: String })
  bannedBy: string;

  @Prop()
  avatar: string;

  @Prop({ type: [AddressSchema], default: [] })
  addresses: Address[];

  @Prop({ default: false })
  isEmailVerified: boolean;

  @Prop({ select: false })
  emailVerificationToken: string;

  @Prop({ select: false })
  emailVerificationExpires: Date;

  @Prop({ select: false })
  passwordResetToken: string;

  @Prop({ select: false })
  passwordResetExpires: Date;

  @Prop({ trim: true })
  phone: string;

  @Prop({ default: false })
  phoneVerified: boolean;

  @Prop({ select: false })
  phoneVerificationToken: string;

  @Prop({ select: false })
  phoneVerificationExpires: Date;

  @Prop()
  lastLogin: Date;

  @Prop({ default: true })
  isActive: boolean;

  @Prop({ default: 'en' })
  preferredLanguage: string;

  @Prop({ default: 'USD' })
  preferredCurrency: string;

  @Prop()
  dateOfBirth: Date;

  @Prop()
  gender: string;

  @Prop({ default: false })
  twoFactorEnabled: boolean;

  @Prop({ select: false })
  twoFactorSecret: string;

  @Prop({
    type: [
      {
        token: String,
        createdAt: { type: Date, default: Date.now },
        expiresAt: Date,
        deviceInfo: String,
      },
    ],
    select: false,
    default: [],
  })
  refreshTokens: RefreshTokenDocument[];

  @Prop({ default: 0 })
  loginAttempts: number;

  @Prop()
  lockUntil: Date;

  @Prop({ default: false })
  newsletter: boolean;

  @Prop()
  termsAcceptedAt: Date;

  @Prop()
  privacyPolicyAcceptedAt: Date;

  // TypeScript Definition
  validatePassword: (password: string) => Promise<boolean>;
}

export const UserSchema = SchemaFactory.createForClass(User);

// Virtual for full name
UserSchema.virtual('fullName').get(function (this: User) {
  return `${this.firstName} ${this.lastName}`;
});

// Runtime Method Implementation
UserSchema.methods.validatePassword = async function (
  password: string,
): Promise<boolean> {
  return bcrypt.compare(password, this.password);
};

// Ensure virtuals are included in JSON
UserSchema.set('toJSON', { virtuals: true });
UserSchema.set('toObject', { virtuals: true });

// Define indexes
UserSchema.index({ email: 1 }, { unique: true });
UserSchema.index({ username: 1 }, { unique: true, sparse: true });
UserSchema.index({ phone: 1 });
UserSchema.index({ role: 1 });
UserSchema.index({ status: 1 });

// Composite index for admin queries
UserSchema.index({ role: 1, status: 1 });

// Text index for search functionality
UserSchema.index({
  firstName: 'text',
  lastName: 'text',
  email: 'text',
  username: 'text',
});

// Index for account security checks
UserSchema.index(
  { lockUntil: 1 },
  {
    sparse: true,
    expireAfterSeconds: 0, // Auto-remove when lockUntil expires
  },
);

// Index for social logins
UserSchema.index({ googleId: 1 }, { unique: true, sparse: true });
UserSchema.index({ githubId: 1 }, { unique: true, sparse: true });

// TTL index to auto-delete verification tokens
UserSchema.index(
  { emailVerificationExpires: 1 },
  {
    expireAfterSeconds: 0,
    sparse: true,
  },
);

UserSchema.index(
  { passwordResetExpires: 1 },
  {
    expireAfterSeconds: 0,
    sparse: true,
  },
);
