import { timingSafeEqual } from 'node:crypto';
import { CanActivate, ExecutionContext, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import type { Request } from 'express';
import { APP_CONFIG, AppConfig } from '../config/config';

/** Bearer-token check for state-changing endpoints. Disabled only when no token is configured (local use). */
@Injectable()
export class ApiTokenGuard implements CanActivate {
  constructor(@Inject(APP_CONFIG) private readonly config: AppConfig) {}

  canActivate(ctx: ExecutionContext): boolean {
    const expected = this.config.apiToken;
    if (!expected) return true;
    const header = ctx.switchToHttp().getRequest<Request>().headers.authorization || '';
    const got = Buffer.from(header.replace(/^Bearer\s+/i, ''));
    const want = Buffer.from(expected);
    if (got.length !== want.length || !timingSafeEqual(got, want)) throw new UnauthorizedException('missing or invalid API token');
    return true;
  }
}
