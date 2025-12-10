// src/storage/dto/file.input.ts
import { Field, InputType, registerEnumType } from '@nestjs/graphql';
import { IsEnum, IsOptional, IsString } from 'class-validator';
import { FileTypeEnum } from '../schemas/file.schema';

registerEnumType(FileTypeEnum, {
  name: 'FileType',
  description: 'Type of file being uploaded',
});

@InputType()
export class UploadFileInput {
  @Field(() => FileTypeEnum)
  @IsEnum(FileTypeEnum)
  type: FileTypeEnum;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  relatedEntity?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  relatedEntityId?: string;
}
