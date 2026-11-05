import 'reflect-metadata';
import { INestApplication, Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import type { NextFunction, Request, Response } from 'express';
import { AppModule } from './app.module';
import { AppConfig, loadConfig } from './config/config';

/** Baseline security headers for every response (the dashboard and reports override CSP per route). */
export function securityHeaders(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('cross-origin-opener-policy', 'same-origin');
  res.setHeader('permissions-policy', 'camera=(), microphone=(), geolocation=()');
  if (!res.getHeader('x-frame-options')) res.setHeader('x-frame-options', 'DENY');
  next();
}

/** Shared HTTP setup (also used by the e2e tests). Create the app with { rawBody: true } for webhook signatures. */
export function configureApp(app: NestExpressApplication): NestExpressApplication {
  app.useBodyParser('json', { limit: '25mb' });
  app.use(securityHeaders);
  app.disable('x-powered-by');
  app.enableShutdownHooks();
  return app;
}

export async function createApp(overrides: Partial<AppConfig> = {}): Promise<NestExpressApplication> {
  const app = await NestFactory.create<NestExpressApplication>(AppModule.forRoot(overrides), {
    rawBody: true,
    logger: ['error', 'warn', 'log'],
  });
  return configureApp(app);
}

export async function bootstrap(port = loadConfig().port): Promise<INestApplication> {
  const app = await createApp();
  await app.listen(port);
  const c = loadConfig();
  new Logger('sentinelops').log(
    `listening on http://localhost:${port} (autonomy L${c.autonomy}, ${c.llm.apiKey ? `LLM ${c.llm.model}` : 'offline agent'})`,
  );
  return app;
}

if (require.main === module) {
  bootstrap().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
