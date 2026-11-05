import { Module } from '@nestjs/common';
import { GithubService } from './github.service';
import { JobsService } from './jobs.service';
import { WebhookController } from './webhook.controller';
import { WebhookService } from './webhook.service';

@Module({
  controllers: [WebhookController],
  providers: [GithubService, JobsService, WebhookService],
  exports: [GithubService, JobsService, WebhookService],
})
export class GithubModule {}
