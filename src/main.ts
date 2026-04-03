import 'dotenv/config';
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import * as express from 'express';
import * as multer from 'multer';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { logger: ['error', 'warn', 'log'] });

  app.enableCors({
    origin: process.env.FRONTEND_URL || '*',
    credentials: true,
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  });

  const server = app.getHttpAdapter().getInstance();
  server.use(express.json());
  server.use(express.urlencoded({ extended: true }));
  server.use(multer().any());

  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: false, transform: true }));

  const config = new DocumentBuilder()
    .setTitle('CRM Integration API')
    .setVersion('2.0.0')
    .addBearerAuth({ type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }, 'jwt')
    .addTag('Auth', 'Issue JWT tokens')
    .addTag('CRM-Connect', 'Connect and manage CRM integrations (JWT required)')
    .addTag('CRM-Detail', 'Detail endpoints - dynamic and all_detail (no JWT)')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  delete document.components?.schemas;
  SwaggerModule.setup('docs', app, document, {
    swaggerOptions: { persistAuthorization: true },
  });

  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(`\n running on http://localhost:${port}`);
  console.log(`📖 Swagger docs:         http://localhost:${port}/docs`);
}
bootstrap();
