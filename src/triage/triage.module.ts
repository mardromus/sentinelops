import { Module } from '@nestjs/common';
import { TriageService } from './triage.service';

@Module({
  providers: [TriageService],
  exports: [TriageService],
})
export class TriageModule {}
