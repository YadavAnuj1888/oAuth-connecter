import {
  Entity, Column, PrimaryGeneratedColumn,
  CreateDateColumn, UpdateDateColumn,
  Index, ManyToOne, JoinColumn,
} from 'typeorm';
import { TenantEntity } from './tenant.entity';

@Entity('crm_integrations')
@Index(['tenantId', 'provider'], { unique: true })
@Index(['tenantId', 'isActive', 'createdAt'])
export class IntegrationEntity {

  @PrimaryGeneratedColumn('increment')
  id: number;

  // ─── Foreign key to tenants table ─────────────────────────
  @Column({ name: 'tenant_id' })
  tenantId: number;

  @ManyToOne(() => TenantEntity, (t) => t.integrations, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'tenant_id' })
  tenant: TenantEntity;

  // ─── Denormalized for fast queries (matches tenant.account_id) ──
  @Column({ name: 'account_id', length: 100 })
  accountId: string;

  @Column({ name: 'provider', length: 50 })
  provider: string;

  @Column({ name: 'api_domain', length: 500, nullable: true })
  apiDomain: string | null;

  // ─── Encrypted secrets (never selected by default) ────────
  @Column({ name: 'access_token_enc', type: 'text', nullable: true, select: false })
  accessTokenEnc: string | null;

  @Column({ name: 'refresh_token_enc', type: 'text', nullable: true, select: false })
  refreshTokenEnc: string | null;

  @Column({ name: 'credentials_enc', type: 'text', nullable: true, select: false })
  credentialsEnc: string | null;

  @Column({ name: 'client_id_enc', type: 'text', nullable: true, select: false })
  clientIdEnc: string | null;

  @Column({ name: 'client_secret_enc', type: 'text', nullable: true, select: false })
  clientSecretEnc: string | null;

  // ─── Token metadata ───────────────────────────────────────
  @Column({ name: 'token_type', length: 50, nullable: true })
  tokenType: string | null;

  @Column({ name: 'email', length: 255, nullable: true })
  email: string | null;

  @Column({ name: 'expires_at', type: 'datetime', nullable: true })
  expiresAt: Date | null;

  @Column({ name: 'is_active', default: true })
  isActive: boolean;

  @Column({ name: 'refresh_job_id', length: 200, nullable: true })
  refreshJobId: string | null;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  // ─── Virtual (not in DB) — populated by decryptInPlace ────
  accessToken?:  string | null;
  refreshToken?: string | null;
  credentials?:  Record<string, any> | null;

  isTokenExpired(): boolean {
    if (!this.expiresAt) return false;
    return new Date() >= this.expiresAt;
  }

  isTokenExpiringSoon(bufferMinutes = 5): boolean {
    if (!this.expiresAt) return false;
    return new Date(Date.now() + bufferMinutes * 60 * 1000) >= this.expiresAt;
  }
}
