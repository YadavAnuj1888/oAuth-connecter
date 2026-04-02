import { CrmVerifier, ICrmVerifier } from './verifier.registry';
import { VerifyResult } from '../interfaces/crm-adapter.interface';
import { safeFetch } from '../../../common/utils/safe-fetch';

@CrmVerifier('salesforce')
export class SalesforceVerifier implements ICrmVerifier {
  async verify(body: Record<string, any>): Promise<VerifyResult> {
    const { clientId, clientSecret, baseUrl, subDomain, token } = body;
    const sfBase = baseUrl || 'https://login.salesforce.com';

    if (token) {
      try {
        const res  = await safeFetch(`${sfBase}/services/oauth2/userinfo`, {
          headers: { Authorization: `Bearer ${token}` }, timeoutMs: 8000, retries: 1,
        });
        const data = await res.json();
        if (res.ok && data?.user_id) {
          return { userId: data.user_id, accessToken: token, tokenType: 'bearer',
                   apiDomain: subDomain || sfBase };
        }
      } catch (e) { console.warn('[Salesforce] token verify failed:', e); }
    }

    try {
      const res = await safeFetch(`${sfBase}/services/oauth2/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'client_credentials',
               client_id: clientId, client_secret: clientSecret }).toString(),
        timeoutMs: 10000, retries: 1,
      });
      const data = await res.json();
      if (res.ok && data?.access_token) {
        return { userId: data.id?.split('/').pop() || clientId,
                 accessToken: data.access_token, tokenType: data.token_type || 'bearer',
                 apiDomain: subDomain || sfBase };
      }
    } catch (e) { console.warn('[Salesforce] client_credentials failed:', e); }

    return { userId: clientId, accessToken: token || null, tokenType: 'bearer',
             apiDomain: subDomain || sfBase };
  }
}
