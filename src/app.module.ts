// src/app.module.ts - PRODUCTION-READY VERSION
import {
  ApolloServerPluginLandingPageLocalDefault,
  ApolloServerPluginLandingPageProductionDefault,
} from '@apollo/server/plugin/landingPage/default';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { CacheModule } from '@nestjs/cache-manager';
import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { GraphQLModule } from '@nestjs/graphql';
import { MongooseModule } from '@nestjs/mongoose';
import { ThrottlerModule } from '@nestjs/throttler';
import { redisStore } from 'cache-manager-redis-yet';
import { GraphQLError, GraphQLFormattedError } from 'graphql';
import { getComplexity, simpleEstimator } from 'graphql-query-complexity';
import { join } from 'path';
import { AppConfigModule } from './app.config.module';
import { AppConfigService } from './app.config.service';
import { AuthModule } from './auth/auth.module';
import { GqlAllExceptionsFilter } from './common/filters/gql-exception.filter';
import { GqlThrottlerGuard } from './common/guards/gql-throttler.guard';
import { AuditLogInterceptor } from './common/interceptors/audit-log.interceptor';
import { LoggerMiddleware } from './common/middleware/logger.middleware';
import { UsersModule } from './users/users.module';

@Module({
  imports: [
    AppConfigModule,
    ThrottlerModule.forRootAsync({
      imports: [AppConfigModule],
      inject: [AppConfigService],
      useFactory: (config: AppConfigService) => [
        {
          ttl: config.throttleTtl,
          limit: config.throttleLimit,
        },
      ],
    }),
    CacheModule.registerAsync({
      isGlobal: true,
      imports: [AppConfigModule],
      inject: [AppConfigService],
      useFactory: async (configService: AppConfigService) => ({
        store: await redisStore({
          url: configService.redisUri,
          ttl: configService.cacheTtl,
        }),
      }),
    }),
    MongooseModule.forRootAsync({
      imports: [AppConfigModule],
      inject: [AppConfigService],
      useFactory: (configService: AppConfigService) => ({
        uri: configService.mongodbUri,
        retryAttempts: 5,
        retryDelay: 3000,
      }),
    }),
    GraphQLModule.forRootAsync<ApolloDriverConfig>({
      driver: ApolloDriver,
      imports: [AppConfigModule],
      inject: [AppConfigService],
      useFactory: (configService: AppConfigService) => {
        const isDev = configService.isDevelopment;

        return {
          autoSchemaFile: isDev ? join(process.cwd(), 'src/schema.gql') : true,
          sortSchema: true,

          // ✅ Disable introspection in production
          introspection: isDev,

          // ✅ Disable playground completely
          playground: false,

          // ✅ Production-safe CORS
          cors: {
            origin: isDev
              ? [
                  configService.corsOrigin,
                  'https://studio.apollographql.com',
                  'https://sandbox.embed.apollographql.com',
                ]
              : configService.corsOrigin, // Only allow your frontend in production
            credentials: true,
          },

          // ✅ Use appropriate landing page plugin based on environment
          plugins: [
            isDev
              ? ApolloServerPluginLandingPageLocalDefault({
                  embed: true,
                  includeCookies: true,
                })
              : ApolloServerPluginLandingPageProductionDefault({
                  footer: false,
                  graphRef: 'your-graph-id@current', // Replace with your Apollo Studio graph ID
                }),
            {
              async requestDidStart() {
                return {
                  async didResolveOperation({ request, document, schema }) {
                    const operationName = request.operationName;

                    // Skip complexity check for introspection queries in development
                    if (isDev && operationName === 'IntrospectionQuery') {
                      return;
                    }

                    const complexity = getComplexity({
                      schema,
                      operationName: request.operationName,
                      query: document,
                      variables: request.variables,
                      estimators: [simpleEstimator({ defaultComplexity: 1 })],
                    });

                    const maxComplexity = isDev ? 100 : 50; // Higher limit in dev

                    if (complexity > maxComplexity) {
                      throw new GraphQLError(
                        `Query is too complex: ${complexity}. Maximum allowed is ${maxComplexity}`,
                        {
                          extensions: {
                            code: 'QUERY_TOO_COMPLEX',
                            complexity,
                            maxAllowed: maxComplexity,
                          },
                        },
                      );
                    }
                  },
                };
              },
            },
          ],

          context: ({ req, res }) => ({ req, res }),

          // ✅ Production-safe error formatting (hide sensitive info)
          formatError: (formattedError: GraphQLFormattedError, error: any) => {
            // In production, hide internal error details
            if (!isDev) {
              // Only expose safe error codes
              const safeErrors = [
                'UNAUTHENTICATED',
                'FORBIDDEN',
                'BAD_USER_INPUT',
                'GRAPHQL_VALIDATION_FAILED',
                'QUERY_TOO_COMPLEX',
              ];

              const code = formattedError.extensions?.code as string;

              // If it's not a safe error, return generic message
              if (!safeErrors.includes(code)) {
                return {
                  message: 'Internal server error',
                  extensions: {
                    code: 'INTERNAL_SERVER_ERROR',
                  },
                };
              }
            }

            // Return formatted error (with stack trace only in dev)
            return {
              message: formattedError.message,
              extensions: {
                ...formattedError.extensions,
                ...(isDev && error.originalError
                  ? { stacktrace: error.originalError.stack }
                  : {}),
              },
            };
          },

          // ✅ Disable detailed error messages in production
          includeStacktraceInErrorResponses: isDev,
        };
      },
    }),
    UsersModule,
    AuthModule,
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: GqlThrottlerGuard,
    },
    {
      provide: APP_FILTER,
      useClass: GqlAllExceptionsFilter,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: AuditLogInterceptor,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(LoggerMiddleware).forRoutes('*');
  }
}
