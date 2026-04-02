import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { Queue } from 'bullmq';

export const REFRESH_QUEUE_NAME = 'token-refresh';
export interface RefreshJobData  { integrationId: number; }

@Injectable()
export class TokenRefreshQueue implements OnModuleDestroy {
  readonly queue: Queue<RefreshJobData>;

  constructor() {
    this.queue = new Queue<RefreshJobData>(REFRESH_QUEUE_NAME, {
      connection: { url: process.env.REDIS_URL || 'redis://localhost:6379' },
      defaultJobOptions: {
        attempts:         5,
        backoff:          { type: 'exponential', delay: 30000 },
        removeOnComplete: 100,
        removeOnFail:     50,
      },
    });
  }

  async onModuleDestroy() { await this.queue.close(); }

  async scheduleRefresh(integrationId: number, expiresAt: Date): Promise<string> {
    const delay = Math.max(expiresAt.getTime() - Date.now() - 5 * 60 * 1000, 0);
    const jobId = `refresh:${integrationId}:${Date.now()}`;
    await this.queue.add('refresh-token', { integrationId }, { jobId, delay });
    return jobId;
  }

  async cancelJob(jobId: string): Promise<void> {
    const job = await this.queue.getJob(jobId);
    if (job) await job.remove();
  }
}
