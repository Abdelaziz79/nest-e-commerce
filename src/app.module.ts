// src/app.module.ts
import { ApolloServerPluginLandingPageLocalDefault } from '@apollo/server/plugin/landingPage/default';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { CacheModule } from '@nestjs/cache-manager';
import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { GraphQLModule } from '@nestjs/graphql';
import { MongooseModule } from '@nestjs/mongoose';
import { ThrottlerModule } from '@nestjs/throttler';
import { redisStore } from 'cache-manager-redis-yet';
import { GraphQLError } from 'graphql';
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
    // 1. Throttler (Rate Limiting)
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
    // 2. Redis Caching
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
    // 3. Database
    MongooseModule.forRootAsync({
      imports: [AppConfigModule],
      inject: [AppConfigService],
      useFactory: (configService: AppConfigService) => ({
        uri: configService.mongodbUri,
        retryAttempts: 5,
        retryDelay: 3000,
      }),
    }),
    // 4. GraphQL + Complexity
    GraphQLModule.forRootAsync<ApolloDriverConfig>({
      driver: ApolloDriver,
      imports: [AppConfigModule],
      inject: [AppConfigService],
      useFactory: (configService: AppConfigService) => ({
        autoSchemaFile: configService.isDevelopment
          ? join(process.cwd(), 'src/schema.gql')
          : true,
        sortSchema: true,
        playground: false,
        plugins: [
          ApolloServerPluginLandingPageLocalDefault(),
          // Query Complexity Plugin
          {
            async requestDidStart() {
              return {
                async didResolveOperation({ request, document, schema }) {
                  const complexity = getComplexity({
                    schema,
                    operationName: request.operationName,
                    query: document,
                    variables: request.variables,
                    estimators: [simpleEstimator({ defaultComplexity: 1 })],
                  });

                  // Allow max 50 points of complexity per query
                  if (complexity > 50) {
                    throw new GraphQLError(
                      `Query is too complex: ${complexity}. Maximum allowed is 50`,
                    );
                  }
                },
              };
            },
          },
        ],
        context: ({ req, res }) => ({ req, res }),
      }),
    }),
    UsersModule,
    AuthModule,
  ],
  providers: [
    // 5. Register Global Throttler Guard
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
