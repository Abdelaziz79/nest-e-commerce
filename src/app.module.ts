import { ApolloServerPluginLandingPageLocalDefault } from '@apollo/server/plugin/landingPage/default';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { MongooseModule } from '@nestjs/mongoose';
import { join } from 'path';
import { AppConfigModule } from './app.config.module';
import { AppConfigService } from './app.config.service';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';

@Module({
  imports: [
    AppConfigModule,
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
      useFactory: (configService: AppConfigService) => ({
        autoSchemaFile: configService.isDevelopment
          ? join(process.cwd(), 'src/schema.gql')
          : true,

        sortSchema: true,

        playground: false,
        plugins: [ApolloServerPluginLandingPageLocalDefault()],
        context: ({ req, res }) => ({ req, res }),
      }),
    }),
    UsersModule,
    AuthModule,
  ],
})
export class AppModule {}
