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

    const bufferMin = parseInt(process.env.REFRESH_BUFFER_MINUTES || '10');
    const REFRESH_BUFFER_MS = bufferMin * 60 * 1000;
    const delay = Math.max(expiresAt.getTime() - Date.now() - REFRESH_BUFFER_MS, 0);


    const jobId = `refresh-${integrationId}`;
    await this.queue.remove(jobId).catch(() => {});
    await this.queue.add('refresh-token', { integrationId }, {
      jobId,
      delay,
      attempts: 5,
      backoff:  { type: 'exponential', delay: 60_000 },
    });
    return jobId;
  }

  async cancelJob(jobId: string): Promise<void> {
    const job = await this.queue.getJob(jobId);
    if (job) await job.remove();
  }
}
