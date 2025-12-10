// src/storage/config/multer.config.ts
import { BadRequestException } from '@nestjs/common';
import { diskStorage } from 'multer';
import { extname } from 'path';
import { v4 as uuidv4 } from 'uuid';
import { FileTypeEnum } from '../schemas/file.schema';

// File size limits (in bytes)
export const FILE_SIZE_LIMITS = {
  [FileTypeEnum.AVATAR]: 5 * 1024 * 1024, // 5MB
  [FileTypeEnum.PRODUCT_IMAGE]: 10 * 1024 * 1024, // 10MB
  [FileTypeEnum.PRODUCT_THUMBNAIL]: 2 * 1024 * 1024, // 2MB
  [FileTypeEnum.CATEGORY_IMAGE]: 5 * 1024 * 1024, // 5MB
  [FileTypeEnum.DOCUMENT]: 20 * 1024 * 1024, // 20MB
  [FileTypeEnum.OTHER]: 10 * 1024 * 1024, // 10MB
};

// Allowed MIME types per file type
export const ALLOWED_MIME_TYPES = {
  [FileTypeEnum.AVATAR]: ['image/jpeg', 'image/png', 'image/webp'],
  [FileTypeEnum.PRODUCT_IMAGE]: ['image/jpeg', 'image/png', 'image/webp'],
  [FileTypeEnum.PRODUCT_THUMBNAIL]: ['image/jpeg', 'image/png', 'image/webp'],
  [FileTypeEnum.CATEGORY_IMAGE]: ['image/jpeg', 'image/png', 'image/webp'],
  [FileTypeEnum.DOCUMENT]: [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  ],
  [FileTypeEnum.OTHER]: ['*'], // Allow all types
};

// Directories for different file types
export const UPLOAD_DIRECTORIES = {
  [FileTypeEnum.AVATAR]: 'uploads/avatars',
  [FileTypeEnum.PRODUCT_IMAGE]: 'uploads/products/images',
  [FileTypeEnum.PRODUCT_THUMBNAIL]: 'uploads/products/thumbnails',
  [FileTypeEnum.CATEGORY_IMAGE]: 'uploads/categories',
  [FileTypeEnum.DOCUMENT]: 'uploads/documents',
  [FileTypeEnum.OTHER]: 'uploads/other',
};

export function getMulterOptions(fileType: FileTypeEnum) {
  return {
    storage: diskStorage({
      destination: (req, file, cb) => {
        const uploadPath = UPLOAD_DIRECTORIES[fileType];
        cb(null, uploadPath);
      },
      filename: (req, file, cb) => {
        const uniqueSuffix = `${Date.now()}-${uuidv4()}`;
        const ext = extname(file.originalname);
        cb(null, `${uniqueSuffix}${ext}`);
      },
    }),
    fileFilter: (req, file, cb) => {
      const allowedTypes = ALLOWED_MIME_TYPES[fileType];

      if (allowedTypes.includes('*') || allowedTypes.includes(file.mimetype)) {
        cb(null, true);
      } else {
        cb(
          new BadRequestException(
            `Invalid file type. Allowed types: ${allowedTypes.join(', ')}`,
          ),
          false,
        );
      }
    },
    limits: {
      fileSize: FILE_SIZE_LIMITS[fileType],
    },
  };
}

// Image optimization settings
export const IMAGE_OPTIMIZATION = {
  [FileTypeEnum.AVATAR]: {
    width: 400,
    height: 400,
    quality: 90,
    format: 'webp',
  },
  [FileTypeEnum.PRODUCT_IMAGE]: {
    width: 1200,
    height: 1200,
    quality: 85,
    format: 'webp',
  },
  [FileTypeEnum.PRODUCT_THUMBNAIL]: {
    width: 300,
    height: 300,
    quality: 80,
    format: 'webp',
  },
  [FileTypeEnum.CATEGORY_IMAGE]: {
    width: 800,
    height: 600,
    quality: 85,
    format: 'webp',
  },
};

// Image variants (different sizes)
export const IMAGE_VARIANTS = {
  [FileTypeEnum.AVATAR]: [
    { name: 'small', width: 100, height: 100 },
    { name: 'medium', width: 200, height: 200 },
    { name: 'large', width: 400, height: 400 },
  ],
  [FileTypeEnum.PRODUCT_IMAGE]: [
    { name: 'thumbnail', width: 150, height: 150 },
    { name: 'small', width: 300, height: 300 },
    { name: 'medium', width: 600, height: 600 },
    { name: 'large', width: 1200, height: 1200 },
  ],
  [FileTypeEnum.CATEGORY_IMAGE]: [
    { name: 'small', width: 200, height: 150 },
    { name: 'medium', width: 400, height: 300 },
    { name: 'large', width: 800, height: 600 },
  ],
};
