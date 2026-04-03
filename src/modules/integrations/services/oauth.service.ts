import { Injectable, BadRequestException, UnauthorizedException, NotFoundException, Logger } from '@nestjs/common';
import * as crypto from 'crypto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { IntegrationEntity }    from '../entities/integration.entity';
import { RedisOAuthStateStore } from '../store/redis-oauth-state.store';
import { EncryptionService }    from '../../../common/crypto/encryption.service';
import { TokenRefreshQueue }    from '../queues/token-refresh.queue';
import { getProviderConfig, OAuthProviderConfig } from '../providers/crm.providers';
import { safeFetch }            from '../../../common/utils/safe-fetch';
import { normalizeToken }       from '../../../common/utils/normalize-token';

@Injectable()
export class OAuthService {
  private readonly logger = new Logger(OAuthService.name);

  constructor(
    @InjectRepository(IntegrationEntity)
    private readonly repo:         Repository<IntegrationEntity>,
    private readonly stateStore:   RedisOAuthStateStore,
    private readonly encryption:   EncryptionService,
    private readonly refreshQueue: TokenRefreshQueue,
  ) {}

  async getAuthUrl(
    provider: string,
    accountId: string,
    body: Record<string, any> = {},
  ): Promise<Record<string, string> | null> {
    const config = getProviderConfig(provider) as OAuthProviderConfig;
    if (config.authType !== 'oauth') throw new BadRequestException(`${provider} does not use OAuth.`);

    const clientId     = body.client_id     || process.env[`${provider.toUpperCase()}_CLIENT_ID`];
    const clientSecret = body.client_secret || process.env[`${provider.toUpperCase()}_CLIENT_SECRET`];
    if (!clientId || !clientSecret) {
      this.logger.warn(`Missing OAuth config for provider: ${provider}`);
      return null;
    }

    const redirectUri = body.redirect_uri || config.redirectUrl;
    const state       = crypto.randomBytes(32).toString('hex');

    let codeVerifier:  string | null = null;
    let codeChallenge: string | null = null;
    if (config.pkce) {
      codeVerifier  = crypto.randomBytes(32).toString('base64url');
      codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    }

    let authUrl = config.authUrl;
    const meta: Record<string, string> = {};
    if (config.dynamicAuthUrl) {
      const subdomain = body.subdomain;
      if (!subdomain) throw new BadRequestException(`${provider} requires body.subdomain.`);
      authUrl = authUrl.replace('{subdomain}', subdomain);
      meta.subdomain = subdomain;
    }

    await this.stateStore.save(state, {
      provider, accountId, codeVerifier, createdAt: Date.now(),
      clientId, clientSecret,
      ...(Object.keys(meta).length ? { meta } : {}),
    });

    const params: Record<string, string> = {
      client_id:     clientId,
      redirect_uri:  redirectUri,
      response_type: 'code',
      state,
      access_type:   'offline',
    };

    if (config.scopes.length > 0) {
      params.scope = config.scopes.join(config.scopeSeparator);
    }
    if (config.promptConsent)    { params.prompt = 'consent'; }
    if (provider === 'pipedrive') { delete params.scope; delete params.access_type; }
    if (codeChallenge)            { params.code_challenge = codeChallenge; params.code_challenge_method = 'S256'; }

    const fullAuthUrl = `${authUrl}?${new URLSearchParams(params)}`;
    this.logger.log(`Auth URL generated for provider: ${provider}, accountId: ${accountId}`);
    return { authUrl: fullAuthUrl, state, provider };
  }

  async handleOAuthCallback(
    provider:  string,
    code:      string,
    state:     string,
    accountId: string,
    query:     Record<string, string> = {},
  ): Promise<IntegrationEntity> {
    const config = getProviderConfig(provider) as OAuthProviderConfig;
    if (config.authType !== 'oauth') throw new BadRequestException(`${provider} is not OAuth.`);

    const stateData = await this.stateStore.verifyAndDelete(state, provider, accountId);
    if (!stateData) throw new UnauthorizedException('Invalid, expired, or tenant-mismatched OAuth state.');

    const clientId     = stateData.clientId     || process.env[`${provider.toUpperCase()}_CLIENT_ID`];
    const clientSecret = stateData.clientSecret || process.env[`${provider.toUpperCase()}_CLIENT_SECRET`];
    if (!clientId || !clientSecret) throw new BadRequestException(`Missing OAuth credentials for ${provider}.`);

    const subdomain = stateData.meta?.subdomain;
    const tokenUrlOverride = subdomain && config.dynamicAuthUrl
      ? config.tokenUrl.replace('{subdomain}', subdomain)
      : undefined;

    const rawToken   = await this.exchangeCodeForToken({
      config, clientId, clientSecret, code,
      redirectUri: config.redirectUrl,
      codeVerifier: stateData.codeVerifier,
      tokenUrlOverride,
    });
    const normalized = normalizeToken(rawToken);
    if (!normalized.accessToken) throw new BadRequestException('Token exchange returned no access_token.');

    const apiDomain = rawToken.instance_url || this.resolveApiDomain(config, query, subdomain);

    return this.upsertIntegration({
      accountId, provider, apiDomain,
      accessToken:  normalized.accessToken,
      refreshToken: normalized.refreshToken,
      tokenType:    normalized.tokenType,
      expiresAt:    normalized.expiresAt,
    });
  }

  async exchangeCodeForToken(p: {
    config:            OAuthProviderConfig;
    clientId:          string;
    clientSecret:      string;
    code:              string;
    redirectUri:       string;
    codeVerifier:      string | null;
    tokenUrlOverride?: string;
  }): Promise<Record<string, any>> {
    const tokenUrl = p.tokenUrlOverride || p.config.tokenUrl;
    const headers: Record<string, string> = { 'Accept': 'application/json' };
    let bodyStr: string;

    const baseFields: Record<string, string> = {
      grant_type:   'authorization_code',
      code:         p.code,
      redirect_uri: p.redirectUri,
    };

    if (p.config.tokenContentType === 'json') {
      headers['Content-Type'] = 'application/json';
      const jsonBody: Record<string, string> = { ...baseFields };
      if (p.config.authMethod === 'body') {
        jsonBody.client_id = p.clientId; jsonBody.client_secret = p.clientSecret;
      } else {
        headers['Authorization'] = `Basic ${Buffer.from(`${p.clientId}:${p.clientSecret}`).toString('base64')}`;
      }
      if (p.codeVerifier) jsonBody.code_verifier = p.codeVerifier;
      bodyStr = JSON.stringify(jsonBody);
    } else {
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      const formBody = new URLSearchParams(baseFields);
      if (p.config.authMethod === 'body') {
        formBody.set('client_id', p.clientId); formBody.set('client_secret', p.clientSecret);
      } else {
        headers['Authorization'] = `Basic ${Buffer.from(`${p.clientId}:${p.clientSecret}`).toString('base64')}`;
      }
      if (p.codeVerifier) formBody.set('code_verifier', p.codeVerifier);
      bodyStr = formBody.toString();
    }

    const res = await safeFetch(tokenUrl, { method: 'POST', headers, body: bodyStr, timeoutMs: 15000, retries: 2 });
    if (!res.ok) throw new BadRequestException(`Token exchange failed: ${await res.text()}`);
    return res.json();
  }

  async upsertIntegration(data: {
    accountId:    string;
    provider:     string;
    apiDomain:    string;
    accessToken:  string;
    refreshToken: string | null;
    tokenType:    string;
    expiresAt:    Date | null;
    email?:       string | null;
    credentials?: Record<string, any> | null;
  }): Promise<IntegrationEntity> {
    const existing = await this.repo.findOne({
      where:  { accountId: data.accountId, provider: data.provider },
      select: ['id', 'refreshJobId'],
    });

    const patch = {
      apiDomain:       data.apiDomain,
      tokenType:       data.tokenType,
      expiresAt:       data.expiresAt,
      email:           data.email      ?? null,
      isActive:        true,
      accessTokenEnc:  this.encryption.encrypt(data.accessToken),
      refreshTokenEnc: data.refreshToken ? this.encryption.encrypt(data.refreshToken) : null,
      credentialsEnc:  data.credentials  ? this.encryption.encrypt(JSON.stringify(data.credentials)) : null,
    };

    if (existing?.refreshJobId) {
      await this.refreshQueue.cancelJob(existing.refreshJobId).catch(() => {});
    }

    let entity: IntegrationEntity;
    if (existing) {
      let refreshJobId: string | null = null;
      if (patch.expiresAt && patch.refreshTokenEnc) {
        refreshJobId = await this.refreshQueue.scheduleRefresh(existing.id, patch.expiresAt);
      }
      await this.repo.update(existing.id, { ...patch, ...(refreshJobId ? { refreshJobId } : {}) });
      entity = await this.repo.findOneOrFail({ where: { id: existing.id, accountId: data.accountId } });
    } else {
      entity = await this.repo.save(this.repo.create({ accountId: data.accountId, provider: data.provider, ...patch }));
      if (entity.expiresAt && patch.refreshTokenEnc) {
        const refreshJobId = await this.refreshQueue.scheduleRefresh(entity.id, entity.expiresAt);
        await this.repo.update(entity.id, { refreshJobId });
        entity.refreshJobId = refreshJobId;
      }
    }

    return entity;
  }

  decryptInPlace(entity: IntegrationEntity): IntegrationEntity {
    entity.accessToken  = entity.accessTokenEnc  ? this.encryption.decrypt(entity.accessTokenEnc)  : null;
    entity.refreshToken = entity.refreshTokenEnc ? this.encryption.decrypt(entity.refreshTokenEnc) : null;
    entity.credentials  = entity.credentialsEnc  ? JSON.parse(this.encryption.decrypt(entity.credentialsEnc)) : null;
    return entity;
  }

  async decryptEntity(entity: IntegrationEntity): Promise<IntegrationEntity> {
    if (entity.accessTokenEnc !== undefined) {
      return this.decryptInPlace(entity);
    }
    const full = await this.repo.findOne({
      where:  { id: entity.id as number, accountId: entity.accountId },
      select: ['id','accountId','provider','apiDomain','tokenType','email','expiresAt',
               'isActive','createdAt','updatedAt','accessTokenEnc','refreshTokenEnc','credentialsEnc'],
    });
    if (!full) throw new NotFoundException('Integration not found.');
    return this.decryptInPlace(full);
  }

  async acquireRefreshLock(integrationId: number): Promise<boolean> {
    return this.stateStore.acquireRefreshLock(integrationId);
  }

  async releaseRefreshLock(integrationId: number): Promise<void> {
    return this.stateStore.releaseRefreshLock(integrationId);
  }

  private resolveApiDomain(
    config:         OAuthProviderConfig,
    query:          Record<string, string>,
    metaSubdomain?: string,
  ): string {
    let domain = config.apiDomain;
    if (config.dynamicUrl && (query.shop || query.subdomain)) {
      const sub = query.shop || query.subdomain;
      domain = domain.replace('{shop}', sub).replace('{subdomain}', sub);
    }
    if (config.dynamicAuthUrl && metaSubdomain) {
      domain = domain.replace('{subdomain}', metaSubdomain);
    }
    return domain;
  }
}
