import { NestFactory } from '@nestjs/core';
import type { Request, Response, NextFunction } from 'express';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { LoggingInterceptor } from './common/interceptors/logging.interceptor';
import { AppLogger } from './common/logger/logger.service';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

// This bootstrap function is like aFactory that builds our NestJS app - it creates,
// configures, and starts the entire application server, making it ready to handle requests.
// Fun fact: The number 3001 is used here because 3000 is commonly taken by other services.
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use((req: Request, _res: Response, next: NextFunction) => {
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
      const cookies: Record<string, string> = {};
      cookieHeader.split(';').forEach((cookie) => {
        const parts = cookie.split('=');
        const name = parts[0]?.trim();
        const value = parts.slice(1).join('=')?.trim();
        if (name && value) {
          cookies[name] = decodeURIComponent(value);
        }
      });
      req.cookies = cookies;
    } else {
      req.cookies = {};
    }
    next();
  });

  const port = process.env.PORT ?? 3001;

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

app.useGlobalFilters(
  app.get(HttpExceptionFilter),
);

// const loggingInterceptor = app.get(LoggingInterceptor);
// app.useGlobalInterceptors(loggingInterceptor);
 

  app.useLogger(new AppLogger());

  const config = new DocumentBuilder()
    .setTitle('Pet Adoption API')
    .setDescription('API documentation for the Pet Adoption platform')
    .setVersion('1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        in: 'header',
      },
      'JWT-auth',
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);

  SwaggerModule.setup('api/docs', app, document);

  await app.listen(port, '0.0.0.0');

  console.log(`Application is running on: http://localhost:${port}`);
}

bootstrap();
