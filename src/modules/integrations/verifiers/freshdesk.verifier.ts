import { CrmVerifier, ICrmVerifier } from './verifier.registry';
import { VerifyResult } from '../interfaces/crm-adapter.interface';
import { safeFetch } from '../../../common/utils/safe-fetch';

@CrmVerifier('freshdesk')
export class FreshdeskVerifier implements ICrmVerifier {
  async verify(body: Record<string, any>): Promise<VerifyResult> {
    const { bundleAlias, apiKey } = body;
    try {
      const basicAuth = Buffer.from(`${apiKey}:X`).toString('base64');
      const res  = await safeFetch(`https://${bundleAlias}.freshdesk.com/api/v2/agents/me`, {
        headers: { Authorization: `Basic ${basicAuth}`, 'Content-Type': 'application/json' },
        timeoutMs: 10000, retries: 1,
      });
      const data = await res.json();
      if (res.ok && data?.id) {
        return { userId: String(data.id), accessToken: apiKey, tokenType: 'api_key',
                 email: data.email ?? null, apiDomain: bundleAlias };
      }
    } catch (e) { console.warn('[Freshdesk] verify failed:', e); }
    return { userId: bundleAlias, accessToken: apiKey, tokenType: 'api_key', apiDomain: bundleAlias };
  }
}
