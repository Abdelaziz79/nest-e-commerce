// src/common/filters/gql-exception.filter.ts
import { ArgumentsHost, Catch, HttpException, Logger } from '@nestjs/common';
import { GqlArgumentsHost, GqlExceptionFilter } from '@nestjs/graphql';
import { GraphQLError } from 'graphql';
import { MongoError } from 'mongodb';
import { AppConfigService } from 'src/config/app.config.service';

@Catch()
export class GqlAllExceptionsFilter implements GqlExceptionFilter {
  constructor(private readonly configService: AppConfigService) {}
  private readonly logger = new Logger(GqlAllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost): GraphQLError {
    const gqlHost = GqlArgumentsHost.create(host);
    const info = gqlHost.getInfo();

    let status = 500;
    let message = 'Internal Server Error';
    let code = 'INTERNAL_SERVER_ERROR';
    let validationErrors: any = null;

    // 1. Handle NestJS HTTP Exceptions
    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const response = exception.getResponse();

      if (typeof response === 'object' && response !== null) {
        const res = response as any;

        // Handle validation errors specifically
        if (Array.isArray(res.message)) {
          validationErrors = res.message;
          message = 'Validation failed';
          code = 'VALIDATION_ERROR';
        } else {
          message = res.message || exception.message;
          code = this.getErrorCode(status, res.error);
        }
      } else {
        message = exception.message;
        code = this.getErrorCode(status);
      }
    }
    // 2. Handle MongoDB Errors
    else if (this.isMongoError(exception)) {
      const mongoError = exception as MongoError;

      if (mongoError.code === 11000) {
        status = 409;
        code = 'DUPLICATE_KEY_ERROR';
        message = this.parseDuplicateKeyError(mongoError);
      } else {
        status = 500;
        code = 'DATABASE_ERROR';
        message = 'Database operation failed';
      }
    }
    // 3. Handle Standard JS Errors
    else if (exception instanceof Error) {
      message = exception.message || 'An unexpected error occurred';
      code = 'INTERNAL_SERVER_ERROR';
    }

    // 4. Logging Strategy
    const logContext = {
      path: info?.fieldName,
      operation: info?.operation?.operation,
      variables: info?.variableValues,
    };

    if (status >= 500) {
      this.logger.error(
        `[${code}] ${message}`,
        (exception as Error)?.stack,
        JSON.stringify(logContext),
      );
    } else if (status >= 400) {
      this.logger.warn(`[${code}] ${message}`, JSON.stringify(logContext));
    }

    // 5. Build GraphQL Error Response
    const extensions: any = {
      code,
      status,
      timestamp: new Date().toISOString(),
    };

    // Add validation errors if present
    if (validationErrors) {
      extensions.validationErrors = validationErrors;
    }

    // Add field path for debugging in development
    if (this.configService.isDevelopment && info?.fieldName) {
      extensions.path = info.fieldName;
    }

    // 6. Throw (not return) GraphQLError
    throw new GraphQLError(message, {
      extensions,
      originalError: exception as Error,
    });
  }

  private getErrorCode(status: number, errorName?: string): string {
    if (errorName) return errorName.toUpperCase().replace(/\s+/g, '_');

    const codeMap: Record<number, string> = {
      400: 'BAD_REQUEST',
      401: 'UNAUTHORIZED',
      403: 'FORBIDDEN',
      404: 'NOT_FOUND',
      409: 'CONFLICT',
      422: 'UNPROCESSABLE_ENTITY',
      429: 'TOO_MANY_REQUESTS',
      500: 'INTERNAL_SERVER_ERROR',
      503: 'SERVICE_UNAVAILABLE',
    };

    return codeMap[status] || 'INTERNAL_SERVER_ERROR';
  }

  private isMongoError(exception: unknown): exception is MongoError {
    return (
      exception instanceof Error &&
      'code' in exception &&
      typeof (exception as any).code === 'number'
    );
  }

  private parseDuplicateKeyError(error: MongoError): string {
    const match = error.message.match(
      /index: (.+?) dup key: { (.+?): "(.+?)" }/,
    );
    if (match) {
      const field = match[2];
      return `${field.charAt(0).toUpperCase() + field.slice(1)} already exists`;
    }
    return 'Duplicate entry detected';
  }
}
