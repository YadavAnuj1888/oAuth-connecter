import { Controller, Get, HttpCode, HttpStatus, OnModuleDestroy } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { createClient, RedisClientType } from 'redis';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { IntegrationEntity } from '../../modules/integrations/entities/integration.entity';

@ApiTags('Health')
@Controller('health')
export class HealthController implements OnModuleDestroy {
  private redis: RedisClientType;

  constructor(
    @InjectRepository(IntegrationEntity)
    private readonly repo: Repository<IntegrationEntity>,
  ) {
    this.redis = createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' }) as RedisClientType;
    this.redis.connect().catch(() => {});
  }

  async onModuleDestroy() {
    await this.redis.quit().catch(() => {});
  }

  @Get()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Liveness probe' })
  liveness() {
    return { status: 'ok', uptime: process.uptime(), timestamp: new Date().toISOString() };
  }

  @Get('ready')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Readiness probe — checks DB + Redis' })
  async readiness() {
    const checks: Record<string, { status: string; error?: string }> = {};

    try {
      await this.repo.query('SELECT 1');
      checks.db = { status: 'ok' };
    } catch (e: any) {
      checks.db = { status: 'fail', error: e.message };
    }

    try {
      await this.redis.ping();
      checks.redis = { status: 'ok' };
    } catch (e: any) {
      checks.redis = { status: 'fail', error: e.message };
    }

    const allOk = Object.values(checks).every((c) => c.status === 'ok');
    return { status: allOk ? 'ok' : 'degraded', checks };
  }

  @Get('integrations')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Integration counts by status' })
  async integrations() {
    const rows: { is_active: number; cnt: number; expiring: number }[] = await this.repo.query(`
      SELECT
        is_active,
        COUNT(*) AS cnt,
        SUM(CASE WHEN is_active = 1 AND expires_at IS NOT NULL
                      AND expires_at < DATE_ADD(NOW(), INTERVAL 10 MINUTE)
                 THEN 1 ELSE 0 END) AS expiring
      FROM crm_integrations
      GROUP BY is_active
    `);

    let active = 0, inactive = 0, expiringSoon = 0;
    for (const row of rows) {
      if (Number(row.is_active) === 1) {
        active = Number(row.cnt);
        expiringSoon = Number(row.expiring);
      } else {
        inactive = Number(row.cnt);
      }
    }
    return { active, inactive, expiringSoon };
  }
}
