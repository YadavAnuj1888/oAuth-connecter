import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { TenantEntity } from '../entities/tenant.entity';

@Injectable()
export class TenantService {
  constructor(
    @InjectRepository(TenantEntity)
    private readonly repo: Repository<TenantEntity>,
  ) {}

  async getOrCreate(accountId: string): Promise<TenantEntity> {
    let tenant = await this.repo.findOne({ where: { accountId } });
    if (!tenant) {
      tenant = await this.repo.save(this.repo.create({ accountId, isActive: true }));
    }
    return tenant;
  }

  async findByAccountId(accountId: string): Promise<TenantEntity | null> {
    return this.repo.findOne({ where: { accountId, isActive: true } });
  }
}
