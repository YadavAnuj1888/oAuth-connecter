import { Injectable, NotFoundException, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { IntegrationEntity } from '../entities/integration.entity';
import { EncryptionService } from '../../../common/crypto/encryption.service';
import { OAuthService }      from './oauth.service';
import { TokenRefreshQueue } from '../queues/token-refresh.queue';
import { getProviderConfig, OAuthProviderConfig } from '../providers/crm.providers';
import { safeFetch }         from '../../../common/utils/safe-fetch';
import { normalizeToken }    from '../../../common/utils/normalize-token';

@Injectable()
export class TokenService {
  constructor(
    @InjectRepository(IntegrationEntity)
    private readonly repo:         Repository<IntegrationEntity>,
    private readonly encryption:   EncryptionService,
    private readonly oauthSvc:     OAuthService,
    private readonly refreshQueue: TokenRefreshQueue,
  ) {}

  async getValidToken(accountId: string, provider: string): Promise<IntegrationEntity> {
    const entity = await this.findActiveWithTokens(accountId, provider);
    if (entity.isTokenExpiringSoon(5) && entity.refreshTokenEnc) {
      return this.refreshToken(accountId, provider, entity);
    }
    return this.oauthSvc.decryptInPlace(entity);
  }

  async refreshToken(
    accountId: string,
    provider:  string,
    preloaded?: IntegrationEntity,
  ): Promise<IntegrationEntity> {
    const entity = preloaded ?? await this.findActiveWithTokens(accountId, provider);
    if (!entity.refreshTokenEnc) throw new BadRequestException(`No refresh token for ${provider}. Please reconnect.`);

    const config = getProviderConfig(provider) as OAuthProviderConfig;
    if (config.authType !== 'oauth') throw new BadRequestException(`${provider} is not an OAuth provider.`);

    const clientId     = entity.clientIdEnc     ? this.encryption.decrypt(entity.clientIdEnc)     : null;
    const clientSecret = entity.clientSecretEnc ? this.encryption.decrypt(entity.clientSecretEnc) : null;
    if (!clientId || !clientSecret) {
      throw new BadRequestException(
        `Missing stored OAuth credentials for ${provider}. Please reconnect.`,
      );
    }

    const lockAcquired = await this.oauthSvc.acquireRefreshLock(entity.id);
    if (!lockAcquired) {
      return this.oauthSvc.decryptInPlace(entity);
    }

    try {
      const refreshToken = this.encryption.decrypt(entity.refreshTokenEnc!);
      let   refreshUrl   = config.refreshUrl || config.tokenUrl;

      if (config.dynamicAuthUrl && refreshUrl.includes('{subdomain}')) {
        try {
          const host = new URL(entity.apiDomain!).host;
          refreshUrl = refreshUrl.replace('{subdomain}', host);
        } catch {
          throw new BadRequestException(`Cannot resolve refresh URL for ${provider}: invalid apiDomain "${entity.apiDomain}"`);
        }
      }

      const headers: Record<string, string> = { 'Accept': 'application/json' };
      let   bodyStr: string;
      const baseFields: Record<string, string> = { grant_type: 'refresh_token', refresh_token: refreshToken };

      if (config.tokenContentType === 'json') {
        headers['Content-Type'] = 'application/json';
        const jsonBody: Record<string, string> = { ...baseFields };
        if (config.authMethod === 'body') {
          jsonBody.client_id = clientId; jsonBody.client_secret = clientSecret;
        } else {
          headers['Authorization'] = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
        }
        bodyStr = JSON.stringify(jsonBody);
      } else {
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
        const formBody = new URLSearchParams(baseFields);
        if (config.authMethod === 'basic') {
          headers['Authorization'] = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
        } else {
          formBody.set('client_id', clientId); formBody.set('client_secret', clientSecret);
        }
        bodyStr = formBody.toString();
      }

      const res = await safeFetch(refreshUrl, { method: 'POST', headers, body: bodyStr, timeoutMs: 15000, retries: 3 });

      if (!res.ok) {
        const errorBody = await res.text();
        if (res.status === 401 || res.status === 400) {
          await this.repo.update(entity.id, { isActive: false });
          throw new UnauthorizedException(`Refresh token revoked for ${provider}. Please reconnect.`);
        }
        throw new BadRequestException(`Token refresh failed for ${provider}: ${errorBody}`);
      }

      const raw        = await res.json();
      const normalized = normalizeToken(raw);

      const patch: Partial<IntegrationEntity> = {
        accessTokenEnc: this.encryption.encrypt(normalized.accessToken),
        tokenType:      normalized.tokenType,
        expiresAt:      normalized.expiresAt,
      };
      if (normalized.refreshToken) {
        patch.refreshTokenEnc = this.encryption.encrypt(normalized.refreshToken);
      }

      let refreshJobId: string | undefined;
      if (normalized.expiresAt) {
        refreshJobId = await this.refreshQueue.scheduleRefresh(entity.id, normalized.expiresAt);
      }
      const finalPatch = { ...patch, ...(refreshJobId ? { refreshJobId } : {}) };
      await this.repo.update(entity.id, finalPatch);

      Object.assign(entity, finalPatch);
      return this.oauthSvc.decryptInPlace(entity);

    } finally {
      await this.oauthSvc.releaseRefreshLock(entity.id);
    }
  }

  async disconnect(accountId: string, provider: string): Promise<void> {
    const entity = await this.findActive(accountId, provider);
    if (entity.refreshJobId) await this.refreshQueue.cancelJob(entity.refreshJobId);
    await this.repo.update(entity.id, {
      isActive: false, accessTokenEnc: null,
      refreshTokenEnc: null, credentialsEnc: null, refreshJobId: null,
    });
  }

  async getAllConnected(accountId: string): Promise<IntegrationEntity[]> {
    return this.repo.find({
      where:  { accountId, isActive: true },
      order:  { createdAt: 'DESC' },
      select: ['id','accountId','provider','apiDomain','tokenType','email','expiresAt','isActive','createdAt','updatedAt'],
    });
  }

  async getDetail(accountId: string, provider: string): Promise<Record<string, unknown>> {
    try {
      const entity = await this.getValidToken(accountId, provider);
      return this.formatDetail(provider, entity);
    } catch {
      return { [`${provider}_detail`]: [] };
    }
  }

  async getAllDetail(accountId: string): Promise<Record<string, unknown>> {
    const entities = await this.repo.find({
      where:  { accountId, isActive: true },
      order:  { createdAt: 'DESC' },
      select: ['id','accountId','provider','apiDomain','tokenType','email','expiresAt',
               'isActive','createdAt','updatedAt','accessTokenEnc','refreshTokenEnc','credentialsEnc'],
    });
    if (entities.length === 0) return { user_id: accountId };

    const result: Record<string, unknown> = { user_id: accountId };
    for (const entity of entities) {
      Object.assign(result, this.formatDetail(entity.provider, this.oauthSvc.decryptInPlace(entity)));
    }
    return result;
  }

  async getTokenMeta(accountId: string, provider: string): Promise<IntegrationEntity> {
    return this.findActive(accountId, provider);
  }

  formatDetail(provider: string, entity: IntegrationEntity): Record<string, unknown> {
    return {
      [`${provider}_detail`]: [{
        id:            entity.id,
        user_id:       entity.accountId,
        api_domain:    entity.apiDomain,
        access_token:  entity.accessToken  ?? null,
        refresh_token: entity.refreshToken ?? null,
        token_type:    entity.tokenType    ?? null,
        email:         entity.email        ?? null,
        expires_at:    entity.expiresAt    ?? null,
        created_at:    entity.createdAt,
        updated_at:    entity.updatedAt,
      }],
    };
  }

  private async findActive(accountId: string, provider: string): Promise<IntegrationEntity> {
    const entity = await this.repo.findOne({
      where: { accountId, provider: provider.toLowerCase(), isActive: true },
    });
    if (!entity) throw new NotFoundException(`No active ${provider} connection for account ${accountId}.`);
    return entity;
  }

  private async findActiveWithTokens(accountId: string, provider: string): Promise<IntegrationEntity> {
    const entity = await this.repo.findOne({
      where:  { accountId, provider: provider.toLowerCase(), isActive: true },
      select: ['id','accountId','provider','apiDomain','tokenType','email','expiresAt',
               'isActive','createdAt','updatedAt','refreshJobId',
               'accessTokenEnc','refreshTokenEnc','credentialsEnc',
               'clientIdEnc','clientSecretEnc'],
    });
    if (!entity) throw new NotFoundException(`No active ${provider} connection for account ${accountId}.`);
    return entity;
  }
}
