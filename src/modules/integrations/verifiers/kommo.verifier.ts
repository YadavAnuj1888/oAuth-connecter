import { Logger } from '@nestjs/common';
import { CrmVerifier, ICrmVerifier } from './verifier.registry';
import { VerifyResult } from '../interfaces/crm-adapter.interface';
import { safeFetch } from '../../../common/utils/safe-fetch';

@CrmVerifier('kommo')
export class KommoVerifier implements ICrmVerifier {
  private readonly logger = new Logger(KommoVerifier.name);

  async verify(body: Record<string, any>): Promise<VerifyResult> {
    const { subDomain, token } = body;
    try {
      const res  = await safeFetch(`https://${subDomain}.kommo.com/api/v4/account`, {
        headers: { Authorization: `Bearer ${token}` }, timeoutMs: 8000, retries: 1,
      });
      const data = await res.json();
      if (res.ok && data?.id) {
        return { userId: String(data.id), accessToken: token, tokenType: 'bearer',
                 apiDomain: `https://${subDomain}.kommo.com` };
      }
    } catch (e) { this.logger.warn(`Verify failed: ${e}`); }
    return { userId: subDomain, accessToken: token, tokenType: 'bearer',
             apiDomain: `https://${subDomain}.kommo.com` };
  }
}
