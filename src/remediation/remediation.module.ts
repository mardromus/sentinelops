import { Module } from '@nestjs/common';
import { RemediationService } from './remediation.service';

@Module({
  providers: [RemediationService],
  exports: [RemediationService],
})
export class RemediationModule {}
