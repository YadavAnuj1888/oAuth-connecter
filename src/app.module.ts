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
        JWT_SECRET:             Joi.string().min(32).required(),
        ENCRYPTION_KEY:         Joi.string().min(32).required(),
        REDIS_URL:              Joi.string().required(),
        DB_HOST:                Joi.string().required(),
        DB_PORT:                Joi.number().default(3306),
        DB_USERNAME:            Joi.string().required(),
        DB_PASSWORD:            Joi.string().required(),
        DB_NAME:                Joi.string().required(),
        FRONTEND_URL:           Joi.string().optional(),
        ALLOWED_REDIRECT_HOSTS: Joi.string().optional(),
        INTERNAL_API_KEY:       Joi.string().min(16).optional(),
      }),
      validationOptions: { abortEarly: false },
    }),

    ThrottlerModule.forRoot([{ ttl: 60_000, limit: 60 }]),

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
      extra:       { connectionLimit: 30, connectTimeout: 10_000 },
    }),

    TypeOrmModule.forFeature([IntegrationEntity]),
    IntegrationsModule,
  ],
  controllers: [HealthController],
  providers: [{ provide: APP_GUARD, useClass: ThrottlerGuard }],
})
export class AppModule {}
