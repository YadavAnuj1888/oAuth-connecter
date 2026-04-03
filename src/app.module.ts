// src/app.module.ts
import { Module }        from '@nestjs/common';
import { ConfigModule }  from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import * as Joi          from 'joi';
import { IntegrationsModule } from './modules/integrations/integrations.module';
import { IntegrationEntity }  from './modules/integrations/entities/integration.entity';
import { TenantEntity }       from './modules/integrations/entities/tenant.entity';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: Joi.object({
        PORT:           Joi.number().default(3000),
        JWT_SECRET:     Joi.string().min(32).required(),
        ENCRYPTION_KEY: Joi.string().min(32).required(),
        REDIS_URL:      Joi.string().required(),
        DB_HOST:        Joi.string().required(),
        DB_PORT:        Joi.number().default(3306),
        DB_USERNAME:    Joi.string().required(),
        DB_PASSWORD:    Joi.string().required(),
        DB_NAME:        Joi.string().required(),
      }),
      validationOptions: { abortEarly: false },
    }),

    TypeOrmModule.forRoot({
      type:        'mysql',
      host:        process.env.DB_HOST,
      port:        parseInt(process.env.DB_PORT || '3306'),
      username:    process.env.DB_USERNAME,
      password:    process.env.DB_PASSWORD,
      database:    process.env.DB_NAME,
      entities:    [IntegrationEntity, TenantEntity],
      synchronize: true,   // set false in prod, use migrations
      logging:     ['error'],
      extra:       { connectionLimit: 20 },
    }),

    IntegrationsModule,
  ],
})
export class AppModule {}
