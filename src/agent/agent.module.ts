import { Module } from '@nestjs/common';
import { APP_CONFIG, AppConfig } from '../config/config';
import { RemediationModule } from '../remediation/remediation.module';
import { AgentService, LLM_CLIENT } from './agent.service';
import { OpenAiCompatibleClient } from './llm.client';

@Module({
  imports: [RemediationModule],
  providers: [
    AgentService,
    {
      provide: LLM_CLIENT,
      inject: [APP_CONFIG],
      useFactory: (c: AppConfig) => (c.llm.apiKey ? new OpenAiCompatibleClient(c.llm.baseUrl, c.llm.apiKey, c.llm.model) : null),
    },
  ],
  exports: [AgentService],
})
export class AgentModule {}
