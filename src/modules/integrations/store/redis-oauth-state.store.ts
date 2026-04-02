import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { createClient, RedisClientType } from 'redis';

export interface OAuthState {
  provider:     string;
  accountId:    string;
  codeVerifier: string | null;
  createdAt:    number;
  meta?:        Record<string, string>;
}

const TTL           = 600;
const PREFIX        = 'oauth:state:';
const LOCK_PREFIX   = 'refresh:lock:';
const LOCK_TTL_SECS = 30;

@Injectable()
export class RedisOAuthStateStore implements OnModuleDestroy {
  private client: RedisClientType;

  constructor() {
    this.client = createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' }) as RedisClientType;
    this.client.connect().catch((e) => console.error('[Redis] connect error:', e));
  }

  async onModuleDestroy() { await this.client.quit(); }

  async save(state: string, data: OAuthState): Promise<void> {
    await this.client.setEx(`${PREFIX}${state}`, TTL, JSON.stringify(data));
  }

  async get(state: string): Promise<OAuthState | null> {
    const raw = await this.client.get(`${PREFIX}${state}`);
    return raw ? JSON.parse(raw) : null;
  }

  async delete(state: string): Promise<void> {
    await this.client.del(`${PREFIX}${state}`);
  }

  async verify(state: string, provider: string, accountId: string): Promise<OAuthState | null> {
    const data = await this.get(state);
    if (!data)                        return null;
    if (data.provider  !== provider)  return null;
    if (data.accountId !== accountId) return null;
    return data;
  }

  async verifyAndDelete(state: string, provider: string, accountId: string): Promise<OAuthState | null> {
    const raw = await this.client.getDel(`${PREFIX}${state}`);
    if (!raw) return null;
    const data: OAuthState = JSON.parse(raw);
    if (data.provider !== provider || data.accountId !== accountId) return null;
    return data;
  }

  async acquireRefreshLock(integrationId: number): Promise<boolean> {
    const result = await this.client.set(
      `${LOCK_PREFIX}${integrationId}`,
      '1',
      { NX: true, EX: LOCK_TTL_SECS },
    );
    return result === 'OK';
  }

  async releaseRefreshLock(integrationId: number): Promise<void> {
    await this.client.del(`${LOCK_PREFIX}${integrationId}`);
  }
}
