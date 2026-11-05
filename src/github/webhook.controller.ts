import { Controller, Headers, HttpCode, Inject, Post, RawBodyRequest, Req, Res, ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import type { Request, Response } from 'express';
import { APP_CONFIG, AppConfig } from '../config/config';
import { verifySignature } from './github.service';
import { WebhookService } from './webhook.service';

@Controller('webhooks')
export class WebhookController {
  constructor(
    private readonly webhooks: WebhookService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  /** GitHub App / repository webhook endpoint. Unsigned or mis-signed deliveries are rejected. */
  @Post('github')
  @HttpCode(202)
  receive(
    @Req() req: RawBodyRequest<Request>,
    @Res({ passthrough: true }) res: Response,
    @Headers('x-github-event') event: string,
    @Headers('x-hub-signature-256') signature: string,
  ) {
    if (!this.config.github.webhookSecret) throw new ServiceUnavailableException('GITHUB_WEBHOOK_SECRET is not configured');
    if (!req.rawBody || !verifySignature(this.config.github.webhookSecret, req.rawBody, signature)) throw new UnauthorizedException('invalid webhook signature');
    const out = this.webhooks.handle(String(event || ''), req.body);
    res.status(out.status);
    return out.body;
  }
}
