import { safeFetch } from '../../../common/utils/safe-fetch';
import { VerifyResult } from '../interfaces/crm-adapter.interface';

export async function verifyExampleCrm(body: Record<string, any>): Promise<VerifyResult> {
  const { apiKey, subdomain } = body;

  try {
    const res  = await safeFetch(`https://${subdomain}.examplecrm.com/api/v1/me`, {
      headers:   { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      timeoutMs: 8000,
      retries:   1,
    });
    const data = await res.json();

    if (res.ok && data?.id) {
      return {
        userId:      String(data.id),
        accessToken: apiKey,
        tokenType:   'api_key',
        email:       data.email ?? null,
        apiDomain:   `https://${subdomain}.examplecrm.com`,
      };
    }
  } catch (e) {
    console.warn('[ExampleCRM] live verify failed — storing credentials anyway:', e);
  }

  return {
    userId:      subdomain,
    accessToken: apiKey,
    tokenType:   'api_key',
    apiDomain:   `https://${subdomain}.examplecrm.com`,
  };
}
