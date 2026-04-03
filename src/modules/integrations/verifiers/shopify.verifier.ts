import * as crypto from 'crypto';
import { BadRequestException, Logger } from '@nestjs/common';
import { CrmVerifier, ICrmVerifier } from './verifier.registry';
import { VerifyResult } from '../interfaces/crm-adapter.interface';
import { safeFetch } from '../../../common/utils/safe-fetch';

@CrmVerifier('shopify')
export class ShopifyVerifier implements ICrmVerifier {
  private readonly logger = new Logger(ShopifyVerifier.name);

  async verify(body: Record<string, any>): Promise<VerifyResult> {
    const { subDomain, clientId, token } = body;

    if (token) {
      try {
        const res  = await safeFetch(`${subDomain}/admin/api/2024-01/shop.json`, {
          headers: { 'X-Shopify-Access-Token': token }, timeoutMs: 8000, retries: 1,
        });
        const data = await res.json();
        if (res.ok && data?.shop?.id) {
          return { userId: String(data.shop.id), accessToken: token,
                   tokenType: 'access_token', apiDomain: subDomain };
        }
      } catch (e) { this.logger.warn(`Token verify failed: ${e}`); }
    }

    const nonce       = crypto.randomBytes(16).toString('hex');
    const redirectUri = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/api/oauth/callback/shopify`;
    const authUrl     = `${subDomain}/admin/oauth/authorize?client_id=${clientId}&scope=read_customers,write_customers,read_orders&redirect_uri=${redirectUri}&state=${nonce}`;
    throw new BadRequestException({ message: 'Shopify requires OAuth. Redirect user to authUrl.', authUrl });
  }
}
