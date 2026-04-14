import { Injectable, BadRequestException, UnauthorizedException, NotFoundException, Logger } from '@nestjs/common';
import * as crypto from 'crypto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { IntegrationEntity }    from '../entities/integration.entity';
import { RedisOAuthStateStore } from '../store/redis-oauth-state.store';
import { EncryptionService }    from '../../../common/crypto/encryption.service';
import { TokenRefreshQueue }    from '../queues/token-refresh.queue';
import { getProviderConfig, OAuthProviderConfig } from '../providers/crm.providers';
import { TenantService }        from './tenant.service';
import { safeFetch }            from '../../../common/utils/safe-fetch';
import { normalizeToken }       from '../../../common/utils/normalize-token';

@Injectable()
export class OAuthService {
  private readonly logger = new Logger(OAuthService.name);

  constructor(
    @InjectRepository(IntegrationEntity)
    private readonly integrationRepository: Repository<IntegrationEntity>,
    private readonly stateStore:            RedisOAuthStateStore,
    private readonly encryption:            EncryptionService,
    private readonly refreshQueue:          TokenRefreshQueue,
    private readonly tenantService:         TenantService,
  ) {}

  async buildAuthUrl(
    provider: string,
    accountId: string,
    body: Record<string, any> = {},
  ): Promise<Record<string, string> | null> {
    const config = getProviderConfig(provider) as OAuthProviderConfig;
    if (config.authType !== 'oauth') throw new BadRequestException(`${provider} does not use OAuth.`);

    const clientId     = body.client_id;
    const clientSecret = body.client_secret;
    if (!clientId || !clientSecret) {
      this.logger.warn(`Missing client_id or client_secret for ${provider}, accountId: ${accountId}`);
      return null;
    }

    const defaultRedirect = `${process.env.BASE_URL || 'http://localhost:3000'}/api/oauth/callback/${provider}`;
    const redirectUri = body.redirect_uri || defaultRedirect;

    if (!this.isRedirectUriAllowed(redirectUri)) {
      throw new BadRequestException(`redirect_uri "${redirectUri}" is not in the allowlist.`);
    }

    this.logger.log(`OAuth start — provider=${provider} accountId=${accountId} ` +
                    `clientId=${this.encryption.maskSensitiveValue(clientId)} redirect=${redirectUri}`);

    const state = crypto.randomBytes(32).toString('hex');

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
      if (!subdomain) throw new BadRequestException(`${provider} requires subdomain.`);
      authUrl = authUrl.replace('{subdomain}', subdomain);
      meta.subdomain = subdomain;
    }

    if (config.dynamicRegion) {
      const region = body.region || 'com';
      authUrl = authUrl.replace('{region}', region);
      meta.region = region;
    }

    await this.stateStore.save(state, {
      provider, accountId, codeVerifier, createdAt: Date.now(),
      clientId, clientSecret, redirectUri,
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
    if (config.optionalScopes && config.optionalScopes.length > 0) {
      params.optional_scope = config.optionalScopes.join(config.scopeSeparator);
    }
    if (config.promptConsent) { params.prompt = 'consent'; }
    if (config.rotatesRefreshToken) { delete params.access_type; }
    if (codeChallenge) { params.code_challenge = codeChallenge; params.code_challenge_method = 'S256'; }

    const fullAuthUrl = `${authUrl}?${new URLSearchParams(params)}`;
    this.logger.log(`Auth URL generated — provider: ${provider}, accountId: ${accountId}, redirect: ${redirectUri}`);
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

    const stateData = await this.stateStore.verifyAndDeleteOAuthState(state, provider, accountId);
    if (!stateData) throw new UnauthorizedException('Invalid, expired, or tenant-mismatched OAuth state.');

    const { clientId, clientSecret, redirectUri } = stateData;
    if (!clientId || !clientSecret) throw new BadRequestException(`Missing OAuth credentials for ${provider}.`);

    this.logger.log(`Token exchange — provider: ${provider}, accountId: ${accountId}`);

    const subdomain = stateData.meta?.subdomain;
    let tokenUrlOverride: string | undefined;
    if (subdomain && config.dynamicAuthUrl) {
      tokenUrlOverride = config.tokenUrl.replace('{subdomain}', subdomain);
    }

    let region: string | null = stateData.meta?.region || null;
    if (config.dynamicRegion) {
      region = this.extractRegionFromOAuthQuery(query) || region || 'com';
      tokenUrlOverride = config.tokenUrl.replace('{region}', region);
      this.logger.log(`${provider} region resolved: ${region}`);
    }

    const rawTokenResponse = await this.exchangeCodeForToken({
      config, clientId, clientSecret, code,
      redirectUri,
      codeVerifier: stateData.codeVerifier,
      tokenUrlOverride,
    });
    const normalized = normalizeToken(rawTokenResponse);
    if (!normalized.accessToken) throw new BadRequestException('Token exchange returned no access_token.');

    let apiDomain = rawTokenResponse.instance_url || this.resolveApiDomainUrl(config, query, subdomain);
    if (region && apiDomain.includes('{region}')) {
      apiDomain = apiDomain.replace('{region}', region);
    }

    this.logger.log(`Tokens received — provider: ${provider}, accountId: ${accountId}, storing in DB`);

    return this.saveOrUpdateIntegration({
      accountId, provider, apiDomain,
      accessToken:  normalized.accessToken,
      refreshToken: normalized.refreshToken,
      tokenType:    normalized.tokenType,
      expiresAt:    normalized.expiresAt,
      clientId,
      clientSecret,
      region,
    });
  }

  async exchangeCodeForToken(tokenExchangeParams: {
    config:            OAuthProviderConfig;
    clientId:          string;
    clientSecret:      string;
    code:              string;
    redirectUri:       string;
    codeVerifier:      string | null;
    tokenUrlOverride?: string;
  }): Promise<Record<string, any>> {
    const tokenUrl = tokenExchangeParams.tokenUrlOverride || tokenExchangeParams.config.tokenUrl;
    const headers: Record<string, string> = { 'Accept': 'application/json' };
    let bodyStr: string;

    const baseFields: Record<string, string> = {
      grant_type:   'authorization_code',
      code:         tokenExchangeParams.code,
      redirect_uri: tokenExchangeParams.redirectUri,
    };

    if (tokenExchangeParams.config.tokenContentType === 'json') {
      headers['Content-Type'] = 'application/json';
      const jsonBody: Record<string, string> = { ...baseFields };
      if (tokenExchangeParams.config.authMethod === 'body') {
        jsonBody.client_id = tokenExchangeParams.clientId;
        jsonBody.client_secret = tokenExchangeParams.clientSecret;
      } else {
        headers['Authorization'] = `Basic ${Buffer.from(`${tokenExchangeParams.clientId}:${tokenExchangeParams.clientSecret}`).toString('base64')}`;
      }
      if (tokenExchangeParams.codeVerifier) jsonBody.code_verifier = tokenExchangeParams.codeVerifier;
      bodyStr = JSON.stringify(jsonBody);
    } else {
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      const formBody = new URLSearchParams(baseFields);
      if (tokenExchangeParams.config.authMethod === 'body') {
        formBody.set('client_id', tokenExchangeParams.clientId);
        formBody.set('client_secret', tokenExchangeParams.clientSecret);
      } else {
        headers['Authorization'] = `Basic ${Buffer.from(`${tokenExchangeParams.clientId}:${tokenExchangeParams.clientSecret}`).toString('base64')}`;
      }
      if (tokenExchangeParams.codeVerifier) formBody.set('code_verifier', tokenExchangeParams.codeVerifier);
      bodyStr = formBody.toString();
    }

    const response = await safeFetch(tokenUrl, { method: 'POST', headers, body: bodyStr, timeoutMs: 15000, retries: 2 });
    if (!response.ok) {
      const errorBody = await response.text();
      this.logger.error(`Token exchange failed for ${tokenExchangeParams.config.authUrl}: ${errorBody}`);
      throw new BadRequestException(`Token exchange failed: ${errorBody}`);
    }
    return response.json();
  }

  async saveOrUpdateIntegration(data: {
    accountId:    string;
    provider:     string;
    apiDomain:    string;
    accessToken:  string;
    refreshToken: string | null;
    tokenType:    string;
    expiresAt:    Date | null;
    email?:       string | null;
    credentials?: Record<string, any> | null;
    clientId?:    string;
    clientSecret?: string;
    region?:      string | null;
  }): Promise<IntegrationEntity> {
    const tenant = await this.tenantService.getOrCreate(data.accountId);

    const existing = await this.integrationRepository.findOne({
      where:  { tenantId: tenant.id, accountId: data.accountId, provider: data.provider },
      select: ['id', 'refreshJobId'],
    });

    const encryptedPatch = {
      apiDomain:        data.apiDomain,
      tokenType:        data.tokenType,
      expiresAt:        data.expiresAt,
      email:            data.email      ?? null,
      region:           data.region     ?? null,
      isActive:         true,
      accessTokenEnc:   this.encryption.encrypt(data.accessToken),
      refreshTokenEnc:  data.refreshToken ? this.encryption.encrypt(data.refreshToken) : null,
      credentialsEnc:   data.credentials  ? this.encryption.encrypt(JSON.stringify(data.credentials)) : null,
      clientIdEnc:      data.clientId     ? this.encryption.encrypt(data.clientId)     : null,
      clientSecretEnc:  data.clientSecret ? this.encryption.encrypt(data.clientSecret) : null,
    };

    if (existing?.refreshJobId) {
      await this.refreshQueue.cancelJob(existing.refreshJobId).catch(() => {});
    }

    let entity: IntegrationEntity;
    if (existing) {
      let refreshJobId: string | null = null;
      if (encryptedPatch.expiresAt && encryptedPatch.refreshTokenEnc) {
        refreshJobId = await this.refreshQueue.scheduleRefresh(existing.id, encryptedPatch.expiresAt);
      }
      await this.integrationRepository.update(existing.id, { ...encryptedPatch, ...(refreshJobId ? { refreshJobId } : {}) });
      entity = await this.integrationRepository.findOneOrFail({ where: { id: existing.id, accountId: data.accountId } });
    } else {
      entity = await this.integrationRepository.save(this.integrationRepository.create({ tenantId: tenant.id, accountId: data.accountId, provider: data.provider, ...encryptedPatch }));
      if (entity.expiresAt && encryptedPatch.refreshTokenEnc) {
        const refreshJobId = await this.refreshQueue.scheduleRefresh(entity.id, entity.expiresAt);
        await this.integrationRepository.update(entity.id, { refreshJobId });
        entity.refreshJobId = refreshJobId;
      }
    }

    this.logger.log(`Integration saved — provider: ${data.provider}, accountId: ${data.accountId}, id: ${entity.id}`);
    return entity;
  }

  decryptEntityTokens(entity: IntegrationEntity): IntegrationEntity {
    entity.accessToken  = entity.accessTokenEnc  ? this.encryption.decrypt(entity.accessTokenEnc)  : null;
    entity.refreshToken = entity.refreshTokenEnc ? this.encryption.decrypt(entity.refreshTokenEnc) : null;
    entity.credentials  = entity.credentialsEnc  ? JSON.parse(this.encryption.decrypt(entity.credentialsEnc)) : null;
    return entity;
  }

  async loadAndDecryptEntity(entity: IntegrationEntity): Promise<IntegrationEntity> {
    if (entity.accessTokenEnc !== undefined) {
      return this.decryptEntityTokens(entity);
    }
    const fullEntity = await this.integrationRepository.findOne({
      where:  { id: entity.id as number, accountId: entity.accountId },
      select: ['id','accountId','provider','apiDomain','tokenType','email','expiresAt',
               'isActive','createdAt','updatedAt','accessTokenEnc','refreshTokenEnc','credentialsEnc',
               'clientIdEnc','clientSecretEnc'],
    });
    if (!fullEntity) throw new NotFoundException('Integration not found.');
    return this.decryptEntityTokens(fullEntity);
  }

  async getOAuthState(state: string): Promise<any> {
    return this.stateStore.get(state);
  }

  async acquireRefreshLock(integrationId: number): Promise<boolean> {
    return this.stateStore.acquireRefreshLock(integrationId);
  }

  async releaseRefreshLock(integrationId: number): Promise<void> {
    return this.stateStore.releaseRefreshLock(integrationId);
  }

  private isRedirectUriAllowed(uri: string): boolean {
    try {
      const parsedUrl = new URL(uri);
      const allowedHosts = (process.env.ALLOWED_REDIRECT_HOSTS || 'app.callerdesk.io,localhost,127.0.0.1')
        .split(',').map((s) => s.trim()).filter(Boolean);
      return allowedHosts.some((host) => parsedUrl.hostname === host || parsedUrl.hostname.endsWith(`.${host}`));
    } catch {
      return false;
    }
  }

  private extractRegionFromOAuthQuery(query: Record<string, string>): string {
    const accountsServer = query['accounts-server'] || '';
    const regionMatch = accountsServer.match(/accounts\.zoho\.([a-z.]+)/i);
    return regionMatch ? regionMatch[1] : 'com';
  }

  private resolveApiDomainUrl(
    config:         OAuthProviderConfig,
    query:          Record<string, string>,
    metaSubdomain?: string,
  ): string {
    let domain = config.apiDomain;
    if (config.dynamicUrl && (query.shop || query.subdomain)) {
      const subdomain = query.shop || query.subdomain;
      domain = domain.replace('{shop}', subdomain).replace('{subdomain}', subdomain);
    }
    if (config.dynamicAuthUrl && metaSubdomain) {
      domain = domain.replace('{subdomain}', metaSubdomain);
    }
    return domain;
  }
}
