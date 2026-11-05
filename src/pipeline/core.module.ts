import { Global, Module } from '@nestjs/common';
import { AgentModule } from '../agent/agent.module';
import { RemediationModule } from '../remediation/remediation.module';
import { ScannersModule } from '../scanners/scanners.module';
import { ScanStore } from '../store/scan.store';
import { TriageModule } from '../triage/triage.module';
import { AuditService } from './audit.service';
import { PipelineService } from './pipeline.service';

/** Everything the CLI, the API and the webhook share. */
@Global()
@Module({
  imports: [ScannersModule, TriageModule, RemediationModule, AgentModule],
  providers: [ScanStore, AuditService, PipelineService],
  exports: [ScanStore, AuditService, PipelineService, ScannersModule, TriageModule, RemediationModule, AgentModule],
})
export class CoreModule {}
