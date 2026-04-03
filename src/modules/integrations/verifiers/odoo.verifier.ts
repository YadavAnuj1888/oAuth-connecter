import { Logger } from '@nestjs/common';
import { CrmVerifier, ICrmVerifier } from './verifier.registry';
import { VerifyResult } from '../interfaces/crm-adapter.interface';
import { safeFetch } from '../../../common/utils/safe-fetch';

@CrmVerifier('odoo')
export class OdooVerifier implements ICrmVerifier {
  private readonly logger = new Logger(OdooVerifier.name);

  async verify(body: Record<string, any>): Promise<VerifyResult> {
    const { odooUrl, databaseName, userEmail, apiKey } = body;

    try {
      const res = await safeFetch(`${odooUrl}/web/session/authenticate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'call', id: 1,
          params: { db: databaseName, login: userEmail, password: apiKey } }),
        timeoutMs: 12000, retries: 1,
      });
      const data = await res.json();
      if (data?.result?.uid) {
        const sessionMatch = (res.headers.get('set-cookie') || '').match(/session_id=([^;]+)/);
        return { userId: String(data.result.uid), accessToken: sessionMatch?.[1] || apiKey,
                 tokenType: 'session', email: userEmail, apiDomain: odooUrl };
      }
    } catch (e) { this.logger.warn(`JSON-RPC verify failed: ${e}`); }

    try {
      const escXml = (s: string) =>
        s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
         .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
      const xmlBody = [
        '<?xml version="1.0"?><methodCall><methodName>authenticate</methodName><params>',
        `<param><value><string>${escXml(databaseName)}</string></value></param>`,
        `<param><value><string>${escXml(userEmail)}</string></value></param>`,
        `<param><value><string>${escXml(apiKey)}</string></value></param>`,
        '<param><value><struct></struct></value></param>',
        '</params></methodCall>',
      ].join('');
      const res   = await safeFetch(`${odooUrl}/xmlrpc/2/common`, {
        method: 'POST', headers: { 'Content-Type': 'text/xml' },
        body: xmlBody, timeoutMs: 10000, retries: 1,
      });
      const match = (await res.text()).match(/<value><int>(\d+)<\/int><\/value>/);
      if (match?.[1] && match[1] !== '0') {
        return { userId: match[1], accessToken: apiKey, tokenType: 'api_key',
                 email: userEmail, apiDomain: odooUrl };
      }
    } catch (e) { this.logger.warn(`XML-RPC verify failed: ${e}`); }

    return { userId: userEmail, accessToken: apiKey, tokenType: 'api_key',
             email: userEmail, apiDomain: odooUrl };
  }
}
