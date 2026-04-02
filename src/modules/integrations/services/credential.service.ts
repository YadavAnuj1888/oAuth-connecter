import { Injectable, BadRequestException } from '@nestjs/common';
import { OAuthService } from './oauth.service';
import { getProviderConfig, CredentialProviderConfig } from '../providers/crm.providers';
import { IntegrationEntity } from '../entities/integration.entity';
import { VerifyResult } from '../interfaces/crm-adapter.interface';
import { getVerifier } from '../verifiers/verifier.registry';
import '../verifiers';

@Injectable()
export class CredentialService {
  constructor(private readonly oauthSvc: OAuthService) {}

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
      throw new BadRequestException(`Missing fields for ${provider}: ${missing.join(', ')}`);
    }

    const verifier = getVerifier(provider);
    const result: VerifyResult = verifier
      ? await verifier.verify(body)
      : { userId: accountId, accessToken: null, tokenType: null };

    const apiDomain = result.apiDomain
      || body.odooUrl || body.bitrixUrl || body.baseUrl || body.subDomain || body.bundleAlias
      || '';

    const entity = await this.oauthSvc.upsertIntegration({
      accountId, provider, apiDomain,
      accessToken:  result.accessToken || '',
      refreshToken: null,
      tokenType:    result.tokenType   || 'api_key',
      expiresAt:    null,
      email:        result.email ?? null,
      credentials:  body,
    });

    return this.formatResponse(provider, entity, result.accessToken);
  }

  private formatResponse(
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
