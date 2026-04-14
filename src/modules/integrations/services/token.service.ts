import { Injectable, NotFoundException, BadRequestException, UnauthorizedException, Logger } from '@nestjs/common';
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
  private readonly logger = new Logger(TokenService.name);

  constructor(
    @InjectRepository(IntegrationEntity)
    private readonly repo:         Repository<IntegrationEntity>,
    private readonly encryption:   EncryptionService,
    private readonly oauthService:     OAuthService,
    private readonly refreshQueue: TokenRefreshQueue,
  ) {}

  async getValidToken(accountId: string, provider: string): Promise<IntegrationEntity> {
    const entity = await this.findActiveIntegrationWithTokens(accountId, provider);

    if (entity.isTokenExpired() && entity.refreshTokenEnc) {
      return this.refreshToken(accountId, provider, entity);
    }

    if (entity.isTokenExpiringSoon(10) && entity.refreshTokenEnc) {
      this.triggerBackgroundRefresh(accountId, provider, entity.id);
    }

    return this.oauthService.decryptEntityTokens(entity);
  }

  async getValidAccessToken(accountId: string, provider: string): Promise<string> {
    const entity = await this.getValidToken(accountId, provider);
    if (!entity.accessToken) {
      throw new UnauthorizedException(`No access token available for ${provider}. Reconnect required.`);
    }
    return entity.accessToken;
  }

  private triggerBackgroundRefresh(accountId: string, provider: string, integrationId: number): void {
    this.refreshToken(accountId, provider).catch((err) => {
      this.logger.warn({
        msg:           'Background refresh failed',
        provider,
        accountId,
        integrationId,
        error:         err.message,
      });
    });
  }

  async refreshToken(
    accountId: string,
    provider:  string,
    preloaded?: IntegrationEntity,
  ): Promise<IntegrationEntity> {
    const entity = preloaded ?? await this.findActiveIntegrationWithTokens(accountId, provider);
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

    const lockAcquired = await this.oauthService.acquireRefreshLock(entity.id);
    if (!lockAcquired) {
      this.logger.warn({
        msg:           'Refresh lock busy — waiting for in-flight refresh',
        provider,
        accountId,
        integrationId: entity.id,
      });
      await new Promise((r) => setTimeout(r, 1500));
      const fresh = await this.findActiveIntegrationWithTokens(accountId, provider);
      return this.oauthService.decryptEntityTokens(fresh);
    }

    try {
      const latest = await this.findActiveIntegrationWithTokens(accountId, provider);
      if (!latest.isTokenExpiringSoon(10)) {
        this.logger.log({
          msg:           'Token already fresh — skipping refresh',
          provider,
          accountId,
          integrationId: entity.id,
        });
        return this.oauthService.decryptEntityTokens(latest);
      }
      Object.assign(entity, latest);

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

      if (config.dynamicRegion && entity.region && refreshUrl.includes('{region}')) {
        refreshUrl = refreshUrl.replace('{region}', entity.region);
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
          this.logger.warn({
            msg:           'Refresh token revoked — marking inactive',
            provider,
            accountId,
            integrationId: entity.id,
            status:        res.status,
          });
          await this.repo.update(entity.id, { isActive: false, refreshJobId: null });
          throw new UnauthorizedException(`Refresh token revoked for ${provider}. Please reconnect.`);
        }
        this.logger.error({
          msg:           'Token refresh failed',
          provider,
          accountId,
          integrationId: entity.id,
          status:        res.status,
          body:          errorBody.substring(0, 200),
        });
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
      this.logger.log({
        msg:           'Token refreshed successfully',
        provider,
        accountId,
        integrationId: entity.id,
        expiresAt:     normalized.expiresAt?.toISOString() ?? null,
      });
      return this.oauthService.decryptEntityTokens(entity);

    } catch (err: any) {
      if (err instanceof UnauthorizedException) {
        await this.repo.update(entity.id, { isActive: false, refreshJobId: null });
      }
      throw err;
    } finally {
      await this.oauthService.releaseRefreshLock(entity.id);
    }
  }

  async disconnect(accountId: string, provider: string): Promise<void> {
    const entity = await this.findActiveIntegration(accountId, provider);
    this.logger.log({ msg: 'Disconnecting', provider, accountId, integrationId: entity.id });
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
      return this.formatIntegrationDetail(provider, entity);
    } catch {
      return { [`${provider}_detail`]: [] };
    }
  }

  async getAllDetail(accountId: string): Promise<Record<string, unknown>> {
    const entities = await this.repo.find({
      where:  { accountId, isActive: true },
      order:  { createdAt: 'DESC' },
      select: ['id','accountId','provider','apiDomain','tokenType','email','expiresAt',
               'isActive','createdAt','updatedAt','type','campaignName1','campaignName2','event',
               'accessTokenEnc','refreshTokenEnc','credentialsEnc'],
    });
    if (entities.length === 0) return { user_id: accountId };

    const result: Record<string, unknown> = { user_id: accountId };
    for (const entity of entities) {
      Object.assign(result, this.formatIntegrationDetail(entity.provider, this.oauthService.decryptEntityTokens(entity)));
    }
    return result;
  }

  async getTokenMeta(accountId: string, provider: string): Promise<IntegrationEntity> {
    return this.findActiveIntegration(accountId, provider);
  }

  formatIntegrationDetail(provider: string, entity: IntegrationEntity): Record<string, unknown> {
    const config = getProviderConfig(provider);
    const isOAuth = config.authType === 'oauth';

    let expiresAt: string | null = null;
    let expiresIn: number | null = null;
    if (isOAuth && entity.expiresAt) {
      expiresAt = entity.expiresAt.toISOString();
      expiresIn = Math.max(0, Math.floor((entity.expiresAt.getTime() - Date.now()) / 1000));
    }

    return {
      [`${provider}_detail`]: [{
        id:             entity.id,
        user_id:        entity.accountId,
        api_domain:     entity.apiDomain,
        access_token:   entity.accessToken  ?? null,
        refresh_token:  entity.refreshToken ?? null,
        token_type:     entity.tokenType    ?? null,
        email:          entity.email        ?? null,
        type:           entity.type         ?? null,
        client_id:      null,
        client_secret:  null,
        campaign_name1: entity.campaignName1 ?? null,
        campaign_name2: entity.campaignName2 ?? null,
        event:          entity.event         ?? null,
        expires_at:     expiresAt,
        expires_in:     expiresIn,
        created_at:     entity.createdAt,
        updated_at:     entity.updatedAt,
      }],
    };
  }

  private async findActiveIntegration(accountId: string, provider: string): Promise<IntegrationEntity> {
    const entity = await this.repo.findOne({
      where: { accountId, provider: provider.toLowerCase(), isActive: true },
    });
    if (!entity) throw new NotFoundException(`No active ${provider} connection for account ${accountId}.`);
    return entity;
  }

  private async findActiveIntegrationWithTokens(accountId: string, provider: string): Promise<IntegrationEntity> {
    const entity = await this.repo.findOne({
      where:  { accountId, provider: provider.toLowerCase(), isActive: true },
      select: ['id','accountId','provider','apiDomain','tokenType','email','expiresAt',
               'isActive','createdAt','updatedAt','refreshJobId','region',
               'type','campaignName1','campaignName2','event',
               'accessTokenEnc','refreshTokenEnc','credentialsEnc',
               'clientIdEnc','clientSecretEnc'],
    });
    if (!entity) throw new NotFoundException(`No active ${provider} connection for account ${accountId}.`);
    return entity;
  }
}
