import { Controller, Get, HttpCode, HttpStatus } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { createClient } from 'redis';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { IntegrationEntity } from '../../modules/integrations/entities/integration.entity';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(
    @InjectRepository(IntegrationEntity)
    private readonly repo: Repository<IntegrationEntity>,
  ) {}

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
      const client = createClient({ url: process.env.REDIS_URL });
      await client.connect();
      await client.ping();
      await client.quit();
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
    const total    = await this.repo.count({ where: { isActive: true } });
    const inactive = await this.repo.count({ where: { isActive: false } });
    const expiring = await this.repo
      .createQueryBuilder('i')
      .where('i.isActive = :a', { a: true })
      .andWhere('i.expiresAt IS NOT NULL')
      .andWhere('i.expiresAt < :soon', { soon: new Date(Date.now() + 10 * 60 * 1000) })
      .getCount();
    return { active: total, inactive, expiringSoon: expiring };
  }
}
