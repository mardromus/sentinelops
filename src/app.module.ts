import { DynamicModule, Module } from '@nestjs/common';
import { ScansController } from './api/scans.controller';
import { SystemController } from './api/system.controller';
import { AppConfig } from './config/config';
import { ConfigModule } from './config/config.module';
import { GithubModule } from './github/github.module';
import { KnowledgeModule } from './knowledge/knowledge.module';
import { CoreModule } from './pipeline/core.module';

@Module({})
export class AppModule {
  static forRoot(overrides: Partial<AppConfig> = {}): DynamicModule {
    return {
      module: AppModule,
      imports: [ConfigModule.forRoot(overrides), KnowledgeModule, CoreModule, GithubModule],
      controllers: [ScansController, SystemController],
    };
  }
}

/** Headless context for the CLI: same services, no HTTP. */
@Module({})
export class CliModule {
  static forRoot(overrides: Partial<AppConfig> = {}): DynamicModule {
    return { module: CliModule, imports: [ConfigModule.forRoot(overrides), KnowledgeModule, CoreModule] };
  }
}
