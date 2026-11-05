import { randomUUID } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';

export interface Job {
  id: string;
  kind: string;
  status: 'queued' | 'running' | 'done' | 'failed';
  createdAt: string;
  finishedAt?: string;
  scanId?: string;
  detail?: string;
}

/**
 * In-process job queue: webhooks must answer within seconds, scans take
 * longer. Jobs run one at a time so a burst of pushes cannot exhaust the box.
 */
@Injectable()
export class JobsService {
  private readonly log = new Logger('jobs');
  private readonly jobs = new Map<string, Job>();
  private chain: Promise<void> = Promise.resolve();

  enqueue(kind: string, work: (job: Job) => Promise<void>): Job {
    const job: Job = { id: randomUUID(), kind, status: 'queued', createdAt: new Date().toISOString() };
    this.jobs.set(job.id, job);
    this.chain = this.chain.then(async () => {
      job.status = 'running';
      try {
        await work(job);
        job.status = 'done';
      } catch (e) {
        job.status = 'failed';
        job.detail = (e as Error).message;
        this.log.error(`${kind} ${job.id} failed: ${job.detail}`);
      } finally {
        job.finishedAt = new Date().toISOString();
      }
    });
    if (this.jobs.size > 500) this.jobs.delete(this.jobs.keys().next().value!);
    return job;
  }

  get(id: string): Job | undefined {
    return this.jobs.get(id);
  }

  list(): Job[] {
    return [...this.jobs.values()].reverse().slice(0, 50);
  }

  /** Resolves when everything queued so far has finished (tests, graceful shutdown). */
  idle(): Promise<void> {
    return this.chain;
  }
}
