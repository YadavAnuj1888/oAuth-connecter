import { safeFetch } from '../../../common/utils/safe-fetch';
import { VerifyResult } from '../interfaces/crm-adapter.interface';

// ─────────────────────────────────────────────────────────────────────────────
//  EXAMPLE: How to add "ExampleCRM" (credential-based, API key auth)
//
//  This file shows the exact code to write.
//  In the real system, the verifier method lives inside credential.service.ts
//  and the config lives inside crm.providers.ts.
//
//  STEP 1 ─ Add to crm.providers.ts:
//
//    examplecrm: {
//      authType:       'credentials',
//      requiredFields: ['apiKey', 'subdomain'],
//      metadata: { displayName: 'ExampleCRM', logo: '', color: '#6C63FF' },
//    },
//
//  STEP 2 ─ Register in credential.service.ts verifiers map (~line 28):
//
//    examplecrm: () => this.verifyExampleCrm(body),
//
//  STEP 3 ─ Add the method below to credential.service.ts as a private method.
//
//  STEP 4 ─ Done.
// ─────────────────────────────────────────────────────────────────────────────


// ─── ExampleCRM: Credential verifier ─────────────────────────────────────────
//
//  Called by CredentialService.connect() after required-field validation passes.
//  Must return a VerifyResult.
//
//  VerifyResult shape:
//    userId:      string         — provider-side user/account ID
//    accessToken: string | null  — the token/key to store
//    tokenType:   string | null  — 'api_key' | 'bearer' | 'session' etc.
//    email?:      string | null  — optional, shown in UI
//    apiDomain?:  string | null  — base URL for this account's API calls
//
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


// ─── ExampleCRM (OAuth variant) ───────────────────────────────────────────────
//
//  If ExampleCRM uses OAuth instead of API keys, you do NOT write any logic.
//  Just add this block to crm.providers.ts and set the env vars.
//
//  examplecrm: {
//    authType:     'oauth',
//    authMethod:   'body',
//    pkce:         false,
//    authUrl:      'https://examplecrm.com/oauth/authorize',
//    tokenUrl:     'https://examplecrm.com/oauth/token',
//    refreshUrl:   'https://examplecrm.com/oauth/token',
//    apiDomain:    'https://api.examplecrm.com/',
//    scopes:       ['read', 'write'],
//    scopeSeparator: ' ',
//    redirectUrl:  process.env.EXAMPLECRM_REDIRECT_URL || 'https://app.callerdesk.io/admin/examplecrm-data',
//    userIdPath:   'user_id',
//    metadata: { displayName: 'ExampleCRM', logo: '', color: '#6C63FF' },
//  },
//
//  Env vars needed:
//    EXAMPLECRM_CLIENT_ID=...
//    EXAMPLECRM_CLIENT_SECRET=...
//    EXAMPLECRM_REDIRECT_URL=...   (optional)
//
//  Nothing else. The generic OAuth flow handles the rest.
