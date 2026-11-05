import { Module } from '@nestjs/common';
import { GITHUB_HTTP, GithubService } from './github.service';
import { JobsService } from './jobs.service';
import { WebhookController } from './webhook.controller';
import { REPO_FETCHER, WebhookService } from './webhook.service';

@Module({
  controllers: [WebhookController],
  // null = use the real implementations (fetch / git); tests override these two tokens
  providers: [
    GithubService,
    JobsService,
    WebhookService,
    { provide: GITHUB_HTTP, useValue: null },
    { provide: REPO_FETCHER, useValue: null },
  ],
  exports: [GithubService, JobsService, WebhookService],
})
export class GithubModule {}
