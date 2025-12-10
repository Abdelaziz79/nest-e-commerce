import { PipeTransform, Injectable, ArgumentMetadata } from '@nestjs/common';
import sanitizeHtml from 'sanitize-html'; // Changed from * as sanitizeHtml

@Injectable()
export class SanitizePipe implements PipeTransform {
  transform(value: any, metadata: ArgumentMetadata) {
    if (typeof value === 'string') {
      // Remove HTML tags and sanitize
      return sanitizeHtml(value, {
        allowedTags: [],
        allowedAttributes: {},
      }).trim();
    }

    if (typeof value === 'object' && value !== null) {
      Object.keys(value).forEach((key) => {
        if (typeof value[key] === 'string') {
          value[key] = sanitizeHtml(value[key], {
            allowedTags: [],
            allowedAttributes: {},
          }).trim();
        }
      });
    }

    return value;
  }
}
