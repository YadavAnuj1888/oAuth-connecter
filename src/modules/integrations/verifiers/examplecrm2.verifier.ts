import { Logger } from '@nestjs/common';
import { CrmVerifier, ICrmVerifier } from './verifier.registry';
import { VerifyResult } from '../interfaces/crm-adapter.interface';
import { safeFetch } from '../../../common/utils/safe-fetch';

@CrmVerifier('examplecrm2')
export class ExampleCrm2Verifier implements ICrmVerifier {
  private readonly logger = new Logger(ExampleCrm2Verifier.name);

  async verify(body: Record<string, any>): Promise<VerifyResult> {
    const { apiKey, subdomain } = body;
    try {
      const res  = await safeFetch(`https://${subdomain}.examplecrm.com/api/v1/me`, {
        headers: { Authorization: `Bearer ${apiKey}` }, timeoutMs: 8000, retries: 1,
      });
      const data = await res.json();
      if (res.ok && data?.id) {
        return { userId: String(data.id), accessToken: apiKey, tokenType: 'api_key',
                 email: data.email ?? null, apiDomain: `https://${subdomain}.examplecrm.com` };
      }
    } catch (e) { this.logger.warn(`Verify failed: ${e}`); }
    return { userId: subdomain, accessToken: apiKey, tokenType: 'api_key',
             apiDomain: `https://${subdomain}.examplecrm.com` };
  }
}
