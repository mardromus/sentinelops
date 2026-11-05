import { DynamicModule, Global, Module } from '@nestjs/common';
import { APP_CONFIG, AppConfig, loadConfig } from './config';

@Global()
@Module({})
export class ConfigModule {
  /** Pass overrides (tests, CLI flags) on top of the environment. */
  static forRoot(overrides: Partial<AppConfig> = {}): DynamicModule {
    const base = loadConfig();
    const config: AppConfig = {
      ...base,
      ...overrides,
      llm: { ...base.llm, ...(overrides.llm || {}) },
      github: { ...base.github, ...(overrides.github || {}) },
    };
    return { module: ConfigModule, providers: [{ provide: APP_CONFIG, useValue: config }], exports: [APP_CONFIG] };
  }
}
