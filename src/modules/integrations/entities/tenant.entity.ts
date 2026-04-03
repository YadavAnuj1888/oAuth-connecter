import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn, OneToMany } from 'typeorm';
import { IntegrationEntity } from './integration.entity';

@Entity('tenants')
export class TenantEntity {
  @PrimaryGeneratedColumn('increment')
  id: number;

  @Column({ name: 'account_id', length: 100, unique: true })
  accountId: string;

  @Column({ name: 'company_name', length: 255, nullable: true })
  companyName: string | null;

  @Column({ name: 'email', length: 255, nullable: true })
  email: string | null;

  @Column({ name: 'is_active', default: true })
  isActive: boolean;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  @OneToMany(() => IntegrationEntity, (i) => i.tenant)
  integrations: IntegrationEntity[];
}
