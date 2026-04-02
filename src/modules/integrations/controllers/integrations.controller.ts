import {
  Controller, Post, Get, Delete,
  Param, Body, Query, Req,
  HttpCode, HttpStatus,
  UseGuards, ValidationPipe,
  BadRequestException, UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import * as jwt    from 'jsonwebtoken';
import {
  ApiTags, ApiOperation, ApiResponse, ApiParam, ApiBody,
  ApiBearerAuth, ApiConsumes,
} from '@nestjs/swagger';
import { JwtAuthGuard }      from '../../../common/guards/jwt-auth.guard';
import { OAuthService }      from '../services/oauth.service';
import { TokenService }      from '../services/token.service';
import { CredentialService } from '../services/credential.service';
import { CRM_PROVIDERS }     from '../providers/crm.providers';
import { ConnectRequestDto, OAuthCallbackDto } from '../dto/connect.dto';

type AuthReq = Request & { accountId: string };

const PROVIDER_PARAM = {
  name: 'provider',
  description: 'CRM provider name',
  example: 'hubspot',
  enum: ['hubspot', 'zoho', 'salesforce', 'pipedrive', 'freshsales',
         'freshdesk', 'odoo', 'bitrix24', 'kommo', 'shopify'],
};

const USER_ID_BODY = {
  schema: {
    type: 'object',
    required: ['user_id'],
    properties: {
      user_id: { type: 'string', example: '97106', description: 'Account / tenant ID' },
    },
  },
};

@ApiTags('CRM-Connect')
@ApiBearerAuth('jwt')
@Controller('crm')
@UseGuards(JwtAuthGuard)
export class IntegrationsController {
  constructor(
    private readonly oauthSvc:      OAuthService,
    private readonly tokenSvc:      TokenService,
    private readonly credentialSvc: CredentialService,
  ) {}

  @Post(':provider/connect')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Connect a CRM',
    description:
      '**OAuth CRMs** (hubspot, zoho, salesforce, pipedrive, freshsales): returns `{ authUrl }` — redirect the user there.\n\n' +
      '**Credential CRMs** (freshdesk, odoo, bitrix24, kommo, shopify): pass credentials in the body, receives connection detail.',
  })
  @ApiParam(PROVIDER_PARAM)
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        client_id:    { type: 'string', example: 'my_client_id' },
        redirect_uri: { type: 'string', example: 'https://app.example.com/admin/hubspot-data' },
        shop:         { type: 'string', example: 'myshop', description: 'Shopify shop subdomain' },
        subdomain:    { type: 'string', example: 'mycompany.freshsales.io', description: 'Required for Freshsales' },
        odooUrl:      { type: 'string', example: 'https://myodoo.com' },
        databaseName: { type: 'string', example: 'mydb' },
        userEmail:    { type: 'string', example: 'admin@mycompany.com' },
        apiKey:       { type: 'string', example: 'abc123xyz' },
        bitrixUrl:    { type: 'string', example: 'https://mycompany.bitrix24.com' },
        clientId:     { type: 'string', example: 'my_client_id' },
        clientSecret: { type: 'string', example: 'my_client_secret' },
        bundleAlias:  { type: 'string', example: 'mycompany', description: 'Freshdesk subdomain' },
        subDomain:    { type: 'string', example: 'mycompany', description: 'Kommo subdomain' },
        token:        { type: 'string', example: 'eyJ...' },
        baseUrl:      { type: 'string', example: 'https://login.salesforce.com' },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'OAuth: returns authUrl. Credential: returns connection detail.' })
  @ApiResponse({ status: 400, description: 'Unsupported provider or missing required fields' })
  @ApiResponse({ status: 401, description: 'Missing or invalid JWT' })
  async connect(
    @Param('provider') provider: string,
    @Body(new ValidationPipe({ whitelist: true })) body: ConnectRequestDto,
    @Req() req: AuthReq,
  ) {
    if (!req.accountId) throw new UnauthorizedException('Account identity missing from token.');
    const p      = provider.toLowerCase();
    const config = CRM_PROVIDERS[p];
    if (!config) throw new BadRequestException(`Provider "${p}" is not supported.`);
    if (config.authType === 'oauth') return this.oauthSvc.getAuthUrl(p, req.accountId, body);
    return this.credentialSvc.connect(p, req.accountId, body);
  }

  @Get(':provider/token')
  @ApiOperation({
    summary: 'Get token metadata',
    description: 'Returns token metadata. Actual token values are masked as `****`. Use `/detail` to get decrypted values.',
  })
  @ApiParam(PROVIDER_PARAM)
  @ApiResponse({ status: 200, description: 'Token metadata with masked values' })
  @ApiResponse({ status: 404, description: 'No active connection found' })
  async getToken(@Param('provider') provider: string, @Req() req: AuthReq) {
    if (!req.accountId) throw new UnauthorizedException('Account identity missing from token.');
    const entity = await this.tokenSvc.getTokenMeta(req.accountId, provider.toLowerCase());
    return {
      provider:      entity.provider,
      user_id:       entity.accountId,
      api_domain:    entity.apiDomain,
      access_token:  entity.accessTokenEnc  ? '****' : null,
      refresh_token: entity.refreshTokenEnc ? '****' : null,
      token_type:    entity.tokenType,
      expires_at:    entity.expiresAt,
      created_at:    entity.createdAt,
    };
  }

  @Get(':provider/detail')
  @ApiOperation({
    summary: 'Get decrypted token detail',
    description: 'Returns the decrypted access token and full connection detail. Auto-refreshes if near expiry.',
  })
  @ApiParam(PROVIDER_PARAM)
  @ApiResponse({ status: 200, description: 'Decrypted connection detail' })
  @ApiResponse({ status: 404, description: 'No active connection found' })
  async getDetail(@Param('provider') provider: string, @Req() req: AuthReq) {
    if (!req.accountId) throw new UnauthorizedException('Account identity missing from token.');
    return this.tokenSvc.getDetail(req.accountId, provider.toLowerCase());
  }

  @Post(':provider/refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Force token refresh',
    description: 'Manually triggers an OAuth token refresh. Normally this happens automatically before expiry.',
  })
  @ApiParam(PROVIDER_PARAM)
  @ApiResponse({ status: 200, description: 'Token refreshed successfully' })
  @ApiResponse({ status: 400, description: 'Provider is not OAuth or no refresh token stored' })
  @ApiResponse({ status: 401, description: 'Refresh token revoked — reconnect required' })
  async refresh(@Param('provider') provider: string, @Req() req: AuthReq) {
    if (!req.accountId) throw new UnauthorizedException('Account identity missing from token.');
    const entity = await this.tokenSvc.refreshToken(req.accountId, provider.toLowerCase());
    return {
      provider:      entity.provider,
      user_id:       entity.accountId,
      access_token:  entity.accessToken  ? '****' : null,
      refresh_token: entity.refreshToken ? '****' : null,
      token_type:    entity.tokenType,
      expires_at:    entity.expiresAt,
    };
  }

  @Delete(':provider')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Disconnect a CRM',
    description: 'Marks the integration inactive and wipes all stored tokens. The DB row is kept for audit purposes.',
  })
  @ApiParam(PROVIDER_PARAM)
  @ApiResponse({ status: 200, description: 'Disconnected successfully' })
  @ApiResponse({ status: 404, description: 'No active connection found' })
  async disconnect(@Param('provider') provider: string, @Req() req: AuthReq) {
    if (!req.accountId) throw new UnauthorizedException('Account identity missing from token.');
    await this.tokenSvc.disconnect(req.accountId, provider.toLowerCase());
    return { success: true, provider: provider.toLowerCase(), message: `${provider} disconnected.` };
  }

  @Get('status')
  @ApiOperation({ summary: 'List all connected CRMs', description: 'Returns every active CRM integration for the current account with expiry status.' })
  @ApiResponse({ status: 200, description: 'List of connected integrations' })
  async statusAll(@Req() req: AuthReq) {
    if (!req.accountId) throw new UnauthorizedException('Account identity missing from token.');
    const list = await this.tokenSvc.getAllConnected(req.accountId);
    return {
      user_id:      req.accountId,
      connected:    list.length > 0,
      count:        list.length,
      integrations: list.map((e) => ({
        provider:   e.provider,
        api_domain: e.apiDomain,
        token_type: e.tokenType,
        expires_at: e.expiresAt,
        expired:    e.isTokenExpired(),
        created_at: e.createdAt,
      })),
    };
  }

  @Get(':provider/status')
  @ApiOperation({ summary: 'Check connection status for one CRM' })
  @ApiParam(PROVIDER_PARAM)
  @ApiResponse({ status: 200, description: 'Connection status' })
  async status(@Param('provider') provider: string, @Req() req: AuthReq) {
    if (!req.accountId) throw new UnauthorizedException('Account identity missing from token.');
    try {
      const entity = await this.tokenSvc.getTokenMeta(req.accountId, provider.toLowerCase());
      return { connected: true, provider: provider.toLowerCase(), api_domain: entity.apiDomain,
               token_type: entity.tokenType, expires_at: entity.expiresAt, expired: entity.isTokenExpired() };
    } catch {
      return { connected: false, provider: provider.toLowerCase() };
    }
  }
}

@ApiTags('CRM-Detail')
@Controller('api')
export class CallerdeskController {
  constructor(
    private readonly tokenSvc: TokenService,
    private readonly oauthSvc: OAuthService,
  ) {}

  private async getProviderDetail(provider: string, body: Record<string, any>) {
    const userId = String(body?.user_id || body?.accountId || body?.account_id || '').trim();
    if (!userId) throw new BadRequestException('Missing user_id');
    return this.tokenSvc.getDetail(userId, provider);
  }

  @Post('crm/hubspot/detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'HubSpot — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  @ApiResponse({ status: 200, description: 'HubSpot connection detail' })
  async hubspotDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('hubspot', body); }

  @Post('crm/zoho/detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Zoho — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  @ApiResponse({ status: 200, description: 'Zoho connection detail' })
  async zohoDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('zoho', body); }

  @Post('crm/salesforce/detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Salesforce — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  @ApiResponse({ status: 200, description: 'Salesforce connection detail' })
  async salesforceDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('salesforce', body); }

  @Post('crm/pipedrive/detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Pipedrive — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  @ApiResponse({ status: 200, description: 'Pipedrive connection detail' })
  async pipedriveDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('pipedrive', body); }

  @Post('crm/freshsales/detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Freshsales — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  @ApiResponse({ status: 200, description: 'Freshsales connection detail' })
  async freshsalesDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('freshsales', body); }

  @Post('crm/freshdesk/detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Freshdesk — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  @ApiResponse({ status: 200, description: 'Freshdesk connection detail' })
  async freshdeskDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('freshdesk', body); }

  @Post('crm/odoo/detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Odoo — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  @ApiResponse({ status: 200, description: 'Odoo connection detail' })
  async odooDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('odoo', body); }

  @Post('crm/bitrix24/detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Bitrix24 — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  @ApiResponse({ status: 200, description: 'Bitrix24 connection detail' })
  async bitrix24Detail(@Body() body: Record<string, any>) { return this.getProviderDetail('bitrix24', body); }

  @Post('crm/kommo/detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Kommo — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  @ApiResponse({ status: 200, description: 'Kommo connection detail' })
  async kommoDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('kommo', body); }

  @Post('crm/shopify/detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Shopify — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  @ApiResponse({ status: 200, description: 'Shopify connection detail' })
  async shopifyDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('shopify', body); }

  @Post('all_detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get detail for all connected CRMs', description: 'Returns token detail for every active CRM for the given user_id.' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  @ApiResponse({ status: 200, description: 'All provider details' })
  @ApiResponse({ status: 400, description: 'Missing user_id' })
  async allDetail(@Body() body: Record<string, any>) {
    const userId = String(body?.user_id || '').trim();
    if (!userId) throw new BadRequestException('Missing user_id');
    return this.tokenSvc.getAllDetail(userId);
  }

  @Get('oauth/callback/:provider')
  @ApiOperation({
    summary: 'OAuth callback',
    description: 'The CRM provider redirects here after the user approves access. Not called directly — registered in your CRM app settings.',
  })
  @ApiParam(PROVIDER_PARAM)
  @ApiResponse({ status: 200, description: 'HTML page confirming connection (closes popup)' })
  @ApiResponse({ status: 400, description: 'Invalid state, expired state, or token exchange failure' })
  async oauthCallback(
    @Param('provider') provider: string,
    @Query(new ValidationPipe({ whitelist: true })) query: OAuthCallbackDto & Record<string, string>,
  ) {
    const { code, state, ...rest } = query;
    const stateData = await this.oauthSvc['stateStore'].get(state);
    const accountId = stateData?.accountId || 'unknown';
    try {
      const entity = await this.oauthSvc.handleOAuthCallback(provider.toLowerCase(), code, state, accountId, rest);
      return `<html><body><h2>&#x2705; ${provider} connected!</h2><p>Account: ${entity.accountId}</p><script>window.close();</script></body></html>`;
    } catch (err: any) {
      throw new BadRequestException(`OAuth callback failed for ${provider}: ${err.message}`);
    }
  }
}

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  @Post('token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Issue a JWT',
    description: '⚠ Unauthenticated — returns a signed JWT for any accountId. Restrict before going to production.',
  })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['accountId'],
      properties: {
        accountId: { type: 'string', example: '97106', description: 'Your account / tenant ID' },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'JWT issued' })
  @ApiResponse({ status: 400, description: 'Missing accountId' })
  issueToken(@Body() body: { accountId?: string; account_id?: string }) {
    const accountId = body.accountId || body.account_id;
    if (!accountId) throw new BadRequestException('accountId is required');
    const secret = process.env.JWT_SECRET;
    if (!secret) throw new Error('JWT_SECRET not set');
    const token = jwt.sign({ sub: accountId, accountId }, secret, { expiresIn: '7d' });
    return { token, accountId };
  }
}
