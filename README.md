# CRM Connector Backend — Production Ready

Multi-tenant CRM integration platform. Supports HubSpot, Zoho, Pipedrive, Salesforce, Freshdesk, Odoo, Bitrix24, Kommo, Shopify.

## Quick Start

```bash
cp .env
# Fill in your .env values
npm install
npm run start:dev
```

## Environment Variables

| Key | Required | Description |
|-----|----------|-------------|
| JWT_SECRET | ✅ | Min 32 chars. Used to verify JWT tokens |
| ENCRYPTION_KEY | ✅ | Min 32 chars. AES-256 key for token encryption |
| REDIS_URL | ✅ | Redis connection URL |
| DB_HOST, DB_PORT, DB_USERNAME, DB_PASSWORD, DB_NAME | ✅ | MySQL connection |
| HUBSPOT_CLIENT_ID / SECRET | OAuth | HubSpot OAuth credentials |
| ZOHO_CLIENT_ID / SECRET | OAuth | Zoho OAuth credentials |
| PIPEDRIVE_CLIENT_ID / SECRET | OAuth | Pipedrive OAuth credentials |
| SALESFORCE_CLIENT_ID / SECRET | OAuth | Salesforce OAuth credentials |

## API Endpoints

### Callerdesk-style (form-data, user_id in body)

```
POST /api/freshdesk_detail    body: user_id=97106
POST /api/odoo_detail         body: user_id=97106
POST /api/bitrix_detail       body: user_id=97106
POST /api/hubspot_detail      body: user_id=97106
POST /api/shopify_detail      body: user_id=97106
POST /api/zoho_detail         body: user_id=97106
POST /api/salesforce_detail   body: user_id=97106
POST /api/kommo_detail        body: user_id=97106
POST /api/pipedrive_detail    body: user_id=97106
POST /api/all_detail          body: user_id=97106
GET  /api/oauth/callback/:provider  (called by CRM after login)
```

### JWT-protected endpoints (Authorization: Bearer <token>)

```
POST   /crm/:provider/connect    Connect a CRM (returns authUrl for OAuth)
GET    /crm/:provider/token      Get stored token
GET    /crm/:provider/detail     Get detail in Callerdesk format
POST   /crm/:provider/refresh    Manually refresh token
DELETE /crm/:provider            Disconnect (soft delete)
GET    /crm/status               All connected CRMs
GET    /crm/:provider/status     Single provider status
```

## Connect Freshdesk (curl)

```bash
curl -X POST http://localhost:3000/api/crm/connect/freshdesk \
  -H "Authorization: Bearer YOUR_JWT" \
  -H "Content-Type: application/json" \
  -d '{"bundleAlias":"callerdesk-support","apiKey":"YOUR_API_KEY"}'
```

## Get Detail (Callerdesk format)

```bash
curl -X POST http://localhost:3000/api/freshdesk_detail -F "user_id=97106"
```

## Architecture

- NestJS + TypeORM + MySQL
- AES-256-GCM encryption for all tokens at rest
- Redis for OAuth state (10min TTL, tenant-bound)
- BullMQ for automatic token refresh queue
- JWT guard extracts accountId — no user_id in body needed for JWT endpoints
- Multi-tenant: every DB query filters by account_id
# oAuth-connecter
