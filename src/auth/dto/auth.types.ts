// src/auth/dto/auth.types.ts
import { Field, ObjectType } from '@nestjs/graphql';

// Define UserInfo FIRST before it's used
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

// Now AuthPayload can reference UserInfo
@ObjectType()
export class AuthPayload {
  @Field()
  accessToken: string;

  @Field(() => UserInfo)
  user: UserInfo;
}
