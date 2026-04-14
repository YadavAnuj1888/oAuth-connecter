import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { OAuthService } from './oauth.service';
import { getProviderConfig, CredentialProviderConfig } from '../providers/crm.providers';
import { IntegrationEntity } from '../entities/integration.entity';
import { VerifyResult } from '../interfaces/crm-adapter.interface';
import { getVerifier } from '../verifiers/verifier.registry';
import '../verifiers';

@Injectable()
export class CredentialService {
  private readonly logger = new Logger(CredentialService.name);

  constructor(private readonly oauthService: OAuthService) {}

  async connect(
    provider:  string,
    accountId: string,
    body:      Record<string, any>,
  ): Promise<Record<string, unknown>> {
    const config = getProviderConfig(provider) as CredentialProviderConfig;
    if (config.authType !== 'credentials') {
      throw new BadRequestException(`${provider} uses OAuth, not credentials.`);
    }

    const missing = config.requiredFields.filter((field) => !body[field]);
    if (missing.length > 0) {
      this.logger.warn(`Missing fields for ${provider}: ${missing.join(', ')}`);
      throw new BadRequestException(`Missing fields for ${provider}: ${missing.join(', ')}`);
    }
    this.logger.log(`Connecting ${provider} for accountId: ${accountId}`);

    const verifier = getVerifier(provider);
    const result: VerifyResult = verifier
      ? await verifier.verify(body)
      : { userId: accountId, accessToken: null, tokenType: null };

    const apiDomain = result.apiDomain
      || body.odooUrl || body.bitrixUrl || body.baseUrl || body.subDomain || body.bundleAlias
      || '';

    const safeCredentials: Record<string, any> = {};
    for (const field of config.requiredFields) {
      if (body[field] !== undefined) safeCredentials[field] = body[field];
    }

    const entity = await this.oauthService.saveOrUpdateIntegration({
      accountId, provider, apiDomain,
      accessToken:  result.accessToken || '',
      refreshToken: null,
      tokenType:    result.tokenType   || 'api_key',
      expiresAt:    null,
      email:        result.email ?? null,
      credentials:  safeCredentials,
    });

    return this.formatCredentialResponse(provider, entity, result.accessToken);
  }

  private formatCredentialResponse(
    provider:    string,
    entity:      IntegrationEntity,
    accessToken: string | null,
  ): Record<string, unknown> {
    return {
      [`${provider}_detail`]: [{
        id:            entity.id,
        user_id:       entity.accountId,
        api_domain:    entity.apiDomain,
        access_token:  accessToken ?? null,
        refresh_token: null,
        token_type:    entity.tokenType ?? null,
        email:         entity.email     ?? null,
        created_at:    entity.createdAt,
      }],
    };
  }
}
