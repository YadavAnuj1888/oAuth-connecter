import { Module }        from '@nestjs/common';
import { ConfigModule }  from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import * as Joi          from 'joi';
import { IntegrationsModule } from './modules/integrations/integrations.module';
import { IntegrationEntity }  from './modules/integrations/entities/integration.entity';
import { TenantEntity }       from './modules/integrations/entities/tenant.entity';
import { HealthController }   from './common/health/health.controller';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: Joi.object({
        NODE_ENV:               Joi.string().valid('development','production','test').default('development'),
        PORT:                   Joi.number().default(3000),
        BASE_URL:               Joi.string().optional(),
        FRONTEND_URL:           Joi.string().optional(),
        CORS_ORIGINS:           Joi.string().optional(),
        JWT_SECRET:             Joi.string().min(32).required(),
        JWT_EXPIRATION:         Joi.string().default('7d'),
        ENCRYPTION_KEY:         Joi.string().min(32).required(),
        REDIS_URL:              Joi.string().required(),
        DB_HOST:                Joi.string().required(),
        DB_PORT:                Joi.number().default(3306),
        DB_USERNAME:            Joi.string().required(),
        DB_PASSWORD:            Joi.string().required(),
        DB_NAME:                Joi.string().required(),
        DB_CONNECTION_LIMIT:    Joi.number().default(30),
        DB_CONNECT_TIMEOUT:     Joi.number().default(10000),
        THROTTLE_TTL:           Joi.number().default(60000),
        THROTTLE_LIMIT:         Joi.number().default(60),
        OAUTH_STATE_TTL:        Joi.number().default(600),
        REFRESH_LOCK_TTL:       Joi.number().default(60),
        REFRESH_BUFFER_MINUTES: Joi.number().default(10),
        ALLOWED_REDIRECT_HOSTS: Joi.string().optional(),
        INTERNAL_API_KEY:       Joi.string().min(16).optional(),
      }),
      validationOptions: { abortEarly: false },
    }),

    ThrottlerModule.forRoot([{
      ttl:   parseInt(process.env.THROTTLE_TTL || '60000'),
      limit: parseInt(process.env.THROTTLE_LIMIT || '60'),
    }]),

    TypeOrmModule.forRoot({
      type:        'mysql',
      host:        process.env.DB_HOST,
      port:        parseInt(process.env.DB_PORT || '3306'),
      username:    process.env.DB_USERNAME,
      password:    process.env.DB_PASSWORD,
      database:    process.env.DB_NAME,
      entities:    [IntegrationEntity, TenantEntity],
      synchronize: process.env.NODE_ENV !== 'production',
      logging:     ['error'],
      extra: {
        connectionLimit:  parseInt(process.env.DB_CONNECTION_LIMIT || '30'),
        connectTimeout:   parseInt(process.env.DB_CONNECT_TIMEOUT || '10000'),
      },
    }),

    TypeOrmModule.forFeature([IntegrationEntity]),
    IntegrationsModule,
  ],
  controllers: [HealthController],
  providers: [{ provide: APP_GUARD, useClass: ThrottlerGuard }],
})
export class AppModule {}
