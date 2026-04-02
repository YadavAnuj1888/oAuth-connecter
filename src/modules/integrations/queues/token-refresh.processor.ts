import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { Worker, Job } from 'bullmq';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { IntegrationEntity } from '../entities/integration.entity';
import { REFRESH_QUEUE_NAME, RefreshJobData } from './token-refresh.queue';

@Injectable()
export class TokenRefreshProcessor implements OnModuleDestroy {
  private readonly logger = new Logger(TokenRefreshProcessor.name);
  private worker: Worker<RefreshJobData>;

  private tokenService: { refreshToken: (accountId: string, provider: string) => Promise<any> } | null = null;

  constructor(
    @InjectRepository(IntegrationEntity)
    private readonly repo: Repository<IntegrationEntity>,
  ) {
    this.worker = new Worker<RefreshJobData>(
      REFRESH_QUEUE_NAME,
      async (job) => this.process(job),
      {
        connection:  { url: process.env.REDIS_URL || 'redis://localhost:6379' },
        concurrency: 10,
      },
    );
    this.worker.on('failed',    (job, err) => this.logger.error(`Job ${job?.id} failed: ${err.message}`));
    this.worker.on('completed', (job)      => this.logger.log(`Job ${job.id} completed`));
  }

  setTokenService(svc: { refreshToken: (accountId: string, provider: string) => Promise<any> }) {
    this.tokenService = svc;
  }

  async onModuleDestroy() { await this.worker.close(); }

  private async process(job: Job<RefreshJobData>): Promise<void> {
    const { integrationId } = job.data;
    const entity = await this.repo.findOne({
      where:  { id: integrationId, isActive: true },
      select: ['id', 'accountId', 'provider', 'refreshTokenEnc', 'isActive'],
    });

    if (!entity || !entity.refreshTokenEnc) {
      this.logger.warn(`Skipping refresh for integration ${integrationId} — not found or no refresh token.`);
      return;
    }

    this.logger.log(`Auto-refreshing token: account=${entity.accountId} provider=${entity.provider}`);

    if (this.tokenService) {
      await this.tokenService.refreshToken(entity.accountId, entity.provider);
    }
  }
}
