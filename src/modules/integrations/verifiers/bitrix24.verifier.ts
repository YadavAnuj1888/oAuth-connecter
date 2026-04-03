import { BadRequestException } from '@nestjs/common';
import { CrmVerifier, ICrmVerifier } from './verifier.registry';
import { VerifyResult } from '../interfaces/crm-adapter.interface';
import { safeFetch } from '../../../common/utils/safe-fetch';

@CrmVerifier('bitrix24')
export class Bitrix24Verifier implements ICrmVerifier {
  async verify(body: Record<string, any>): Promise<VerifyResult> {
    let { bitrixUrl, clientId, clientSecret } = body;
    if (bitrixUrl && !bitrixUrl.startsWith('http')) bitrixUrl = `https://${bitrixUrl}`;

    try {
      const res  = await safeFetch(`${bitrixUrl}/rest/profile.json?auth=${clientSecret}`, { timeoutMs: 8000, retries: 1 });
      const data = await res.json();
      if (res.ok && data?.result && !data?.error) {
        return { userId: String(data.result.ID ?? data.result.id ?? clientId),
                 accessToken: clientSecret, tokenType: 'webhook', apiDomain: bitrixUrl };
      }
    } catch (e) { console.warn('[Bitrix24] outbound webhook verify failed:', e); }

    try {
      const res  = await safeFetch(`${bitrixUrl}/rest/1/${clientSecret}/profile.json`, { timeoutMs: 8000, retries: 1 });
      const data = await res.json();
      if (res.ok && data?.result && !data?.error) {
        return { userId: String(data.result.ID ?? data.result.id ?? '1'),
                 accessToken: clientSecret, tokenType: 'inbound_webhook', apiDomain: bitrixUrl };
      }
    } catch (e) { console.warn('[Bitrix24] inbound webhook verify failed:', e); }

    const redirectUri = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/api/oauth/callback/bitrix24`;
    const authUrl     = `${bitrixUrl}/oauth/authorize/?client_id=${clientId}&response_type=code&redirect_uri=${redirectUri}`;
    throw new BadRequestException({ message: 'Bitrix24 requires OAuth. Redirect user to authUrl.', authUrl });
  }
}
