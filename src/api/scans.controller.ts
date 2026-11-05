import { isAbsolute, relative, resolve } from 'node:path';
import { BadRequestException, Body, Controller, ForbiddenException, Get, Header, Inject, NotFoundException, Param, Post, Query, UseGuards } from '@nestjs/common';
import { Severity } from '../common/types';
import { APP_CONFIG, AppConfig } from '../config/config';
import { PipelineService } from '../pipeline/pipeline.service';
import { toHtml } from '../reports/html';
import { toMarkdown } from '../reports/markdown';
import { toSarif } from '../reports/sarif';
import { ScanStore, StoredScan } from '../store/scan.store';
import { ApiTokenGuard } from './auth.guard';

export interface CreateScanDto {
  path?: string;
  ai?: boolean;
  fix?: boolean;
  osv?: boolean;
  external?: boolean;
  failOn?: Severity;
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

@Controller('api/scans')
export class ScansController {
  constructor(
    private readonly pipeline: PipelineService,
    private readonly store: ScanStore,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  /** Only directories under SENTINELOPS_SCAN_ROOTS can be scanned over HTTP. */
  resolveRoot(path: string | undefined): string {
    const roots = this.config.scanRoots.map((r) => resolve(r));
    const target = resolve(roots[0], path || '.');
    const inside = roots.some((r) => {
      const rel = relative(r, target);
      return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
    });
    if (!inside) throw new ForbiddenException(`path is outside the allowed scan roots (${roots.join(', ')})`);
    return target;
  }

  @Post()
  @UseGuards(ApiTokenGuard)
  async create(@Body() body: CreateScanDto = {}) {
    if (body.failOn && !SEVERITIES.includes(body.failOn)) throw new BadRequestException('failOn must be one of ' + SEVERITIES.join(', '));
    const root = this.resolveRoot(body.path);
    const { stored } = await this.pipeline.run({
      root,
      ai: body.ai ?? false,
      fix: body.fix === false ? 'none' : 'propose',
      osv: body.osv,
      external: body.external,
      failOn: body.failOn,
      source: { kind: 'api' },
    });
    return this.brief(stored);
  }

  @Get()
  list(@Query('limit') limit?: string) {
    return this.store.list(Math.min(200, Number(limit) || 50));
  }

  private load(id: string): StoredScan {
    const s = this.store.get(id);
    if (!s) throw new NotFoundException(`scan ${id} not found`);
    return s;
  }

  @Get(':id')
  get(@Param('id') id: string) {
    return this.load(id);
  }

  @Get(':id/sarif')
  @Header('content-type', 'application/sarif+json')
  sarif(@Param('id') id: string) {
    return toSarif(this.load(id).result);
  }

  @Get(':id/report.md')
  @Header('content-type', 'text/markdown; charset=utf-8')
  markdown(@Param('id') id: string) {
    const s = this.load(id);
    return toMarkdown(s.result, { gate: s.gate, agent: s.agent, diff: s.diff });
  }

  @Get(':id/report.html')
  @Header('content-type', 'text/html; charset=utf-8')
  @Header('x-frame-options', 'SAMEORIGIN')
  html(@Param('id') id: string) {
    const s = this.load(id);
    return toHtml(s.result, { gate: s.gate, agent: s.agent, summary: s.summary });
  }

  @Get(':id/findings/:fid/fix.diff')
  @Header('content-type', 'text/x-diff; charset=utf-8')
  fix(@Param('id') id: string, @Param('fid') fid: string) {
    const f = this.load(id).result.findings.find((x) => x.id === fid);
    if (!f?.fix) throw new NotFoundException('no fix for this finding');
    return f.fix.diff;
  }

  private brief(s: StoredScan) {
    return {
      id: s.result.id,
      root: s.result.root,
      gate: s.gate,
      summary: s.summary,
      diff: s.diff,
      agent: s.agent ? { mode: s.agent.mode, summary: s.agent.summary, verdicts: s.agent.verdicts.length, fixes: s.agent.fixes.length } : undefined,
      links: { self: `/api/scans/${s.result.id}`, html: `/api/scans/${s.result.id}/report.html`, sarif: `/api/scans/${s.result.id}/sarif`, markdown: `/api/scans/${s.result.id}/report.md` },
    };
  }
}
