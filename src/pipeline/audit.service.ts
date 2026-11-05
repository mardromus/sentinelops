import { join } from 'node:path';
import { Inject, Injectable } from '@nestjs/common';
import { AuditLog } from '../agent/audit';
import { APP_CONFIG, AppConfig } from '../config/config';

/** One shared, persistent audit trail for every agent and human action. */
@Injectable()
export class AuditService extends AuditLog {
  constructor(@Inject(APP_CONFIG) config: AppConfig) {
    super(join(config.dataDir, 'audit.jsonl'));
  }
}
