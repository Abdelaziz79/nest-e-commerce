// src/storage/dto/file.types.ts
import { Field, ID, ObjectType, registerEnumType } from '@nestjs/graphql';
import { FileStatus, FileTypeEnum } from '../schemas/file.schema';

// Register enums for GraphQL
registerEnumType(FileStatus, {
  name: 'FileStatus',
});

registerEnumType(FileTypeEnum, {
  name: 'FileTypeEnum',
  description: 'Type of file being uploaded',
});

@ObjectType()
export class FileMetadata {
  @Field({ nullable: true })
  width?: number;

  @Field({ nullable: true })
  height?: number;

  @Field({ nullable: true })
  format?: string;

  @Field({ nullable: true })
  aspectRatio?: string;
}

@ObjectType()
export class FileType {
  @Field(() => ID)
  _id: string;

  @Field()
  originalName: string;

  @Field()
  filename: string;

  @Field()
  url: string;

  @Field()
  mimetype: string;

  @Field()
  size: number;

  @Field(() => FileTypeEnum)
  type: FileTypeEnum;

  @Field(() => FileStatus)
  status: FileStatus;

  @Field()
  uploadedBy: string;

  @Field({ nullable: true })
  optimizedUrl?: string;

  @Field({ nullable: true })
  optimizedSize?: number;

  @Field(() => FileMetadata, { nullable: true })
  metadata?: FileMetadata;

  @Field(() => [String], { nullable: true })
  variants?: string[];

  @Field({ nullable: true })
  errorMessage?: string;

  @Field()
  isPublic: boolean;

  @Field()
  createdAt: Date;

  @Field()
  updatedAt: Date;
}

@ObjectType()
export class UploadResponse {
  @Field()
  success: boolean;

  @Field()
  message: string;

  @Field(() => FileType, { nullable: true })
  file: FileType | null;
}

@ObjectType()
export class PaginatedFilesType {
  @Field(() => [FileType])
  files: FileType[];

  @Field()
  total: number;

  @Field()
  page: number;

  @Field()
  limit: number;

  @Field()
  totalPages: number;
}
