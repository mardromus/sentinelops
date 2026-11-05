import { readFileSync } from 'node:fs';
import { Controller, Get, Header, Inject, NotFoundException, Param, Query } from '@nestjs/common';
import { LEVEL_NAMES } from '../agent/policy';
import { APP_CONFIG, AppConfig } from '../config/config';
import { JobsService } from '../github/jobs.service';
import { KnowledgeService } from '../knowledge/knowledge.service';
import { AuditService } from '../pipeline/audit.service';
import { hasFixer } from '../remediation/fixers';
import { assetPath } from '../reports/html';
import { TOOL_VERSION } from '../reports/sarif';
import { RULES } from '../scanners/sast/rules';
import { ScannersService } from '../scanners/scanners.service';

@Controller()
export class SystemController {
  constructor(
    private readonly knowledge: KnowledgeService,
    private readonly audit: AuditService,
    private readonly jobs: JobsService,
    private readonly scanners: ScannersService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  @Get()
  @Header('content-type', 'text/html; charset=utf-8')
  @Header(
    'content-security-policy',
    "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-src 'self'; img-src 'self' data:",
  )
  dashboard() {
    return readFileSync(assetPath('dashboard.html'), 'utf8');
  }

  @Get('api/health')
  health() {
    return {
      status: 'ok',
      version: TOOL_VERSION,
      autonomy: `L${this.config.autonomy} ${LEVEL_NAMES[this.config.autonomy]}`,
      llm: this.config.llm.apiKey
        ? { configured: true, model: this.config.llm.model, baseUrl: this.config.llm.baseUrl }
        : { configured: false, mode: 'offline planner' },
      github: { token: !!this.config.github.token, webhook: !!this.config.github.webhookSecret },
      scanners: this.scanners.list(),
      osv: this.config.osv,
    };
  }

  @Get('api/owasp')
  owasp() {
    return this.knowledge.allOwasp();
  }

  @Get('api/rules')
  rules() {
    return RULES.map((r) => {
      const owasp = [...new Set(r.cwe.map((c) => this.knowledge.cwe(c)?.owasp).filter(Boolean))];
      return {
        id: r.id,
        title: r.title,
        severity: r.severity,
        confidence: r.confidence,
        languages: r.languages,
        cwe: r.cwe,
        owasp,
        autofix: hasFixer(r.id),
      };
    });
  }

  @Get('api/audit')
  auditLog(@Query('limit') limit?: string) {
    const check = this.audit.verify();
    return { ...check, entries: this.audit.tail(Math.min(500, Number(limit) || 100)).reverse() };
  }

  @Get('api/jobs')
  jobList() {
    return this.jobs.list();
  }

  @Get('api/jobs/:id')
  job(@Param('id') id: string) {
    const j = this.jobs.get(id);
    if (!j) throw new NotFoundException('job not found');
    return j;
  }
}
