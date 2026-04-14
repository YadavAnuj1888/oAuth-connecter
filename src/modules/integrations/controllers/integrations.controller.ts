import {
  Controller, Post, Get, Delete,
  Param, Body, Query, Req,
  HttpCode, HttpStatus,
  UseGuards,
  BadRequestException, UnauthorizedException, Logger,
} from '@nestjs/common';
import { Request } from 'express';
import * as jwt    from 'jsonwebtoken';
import {
  ApiTags, ApiOperation, ApiResponse, ApiParam, ApiBody, ApiQuery,
  ApiBearerAuth, ApiConsumes,
} from '@nestjs/swagger';
import { JwtAuthGuard }      from '../../../common/guards/jwt-auth.guard';
import { OAuthService }      from '../services/oauth.service';
import { TokenService }      from '../services/token.service';
import { CredentialService } from '../services/credential.service';
import { CRM_PROVIDERS }     from '../providers/crm.providers';
import { ConnectRequestDto } from '../dto/connect.dto';

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
  private readonly logger = new Logger(IntegrationsController.name);

  constructor(
    private readonly oauthService:      OAuthService,
    private readonly tokenService:      TokenService,
    private readonly credentialService: CredentialService,
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
    @Body() body: ConnectRequestDto,
    @Req() req: AuthReq,
  ) {
    if (!req.accountId) throw new UnauthorizedException('Account identity missing from token.');
    const p      = provider.toLowerCase();
    this.logger.log(`Connect request: ${p}, accountId: ${req.accountId}`);
    const config = CRM_PROVIDERS[p];
    if (!config) throw new BadRequestException(`Provider "${p}" is not supported.`);
    if (config.authType === 'oauth') {
      const result = await this.oauthService.buildAuthUrl(p, req.accountId, body);
      if (!result) throw new BadRequestException(`Missing OAuth config for provider: ${p}`);
      return result;
    }
    return this.credentialService.connect(p, req.accountId, body);
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
    const entity = await this.tokenService.getTokenMeta(req.accountId, provider.toLowerCase());
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
    return this.tokenService.getDetail(req.accountId, provider.toLowerCase());
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
    const entity = await this.tokenService.refreshToken(req.accountId, provider.toLowerCase());
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
    await this.tokenService.disconnect(req.accountId, provider.toLowerCase());
    return { success: true, provider: provider.toLowerCase(), message: `${provider} disconnected.` };
  }

  @Get('status')
  @ApiOperation({ summary: 'List all connected CRMs', description: 'Returns every active CRM integration for the current account with expiry status.' })
  @ApiResponse({ status: 200, description: 'List of connected integrations' })
  async statusAll(@Req() req: AuthReq) {
    if (!req.accountId) throw new UnauthorizedException('Account identity missing from token.');
    const list = await this.tokenService.getAllConnected(req.accountId);
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
      const entity = await this.tokenService.getTokenMeta(req.accountId, provider.toLowerCase());
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
  private readonly logger = new Logger(CallerdeskController.name);

  constructor(
    private readonly tokenService: TokenService,
    private readonly oauthService: OAuthService,
  ) {}

  private async getProviderDetail(provider: string, body: Record<string, any>) {
    const userId = String(body?.user_id || body?.accountId || body?.account_id || '').trim();
    if (!userId) throw new BadRequestException('Missing user_id');
    return this.tokenService.getDetail(userId, provider);
  }

  @Get('crm/:provider/auth')
  @ApiOperation({ summary: 'Get OAuth auth URL — multi-tenant', description: 'Each tenant provides their own OAuth credentials. No server-side env config needed.' })
  @ApiParam(PROVIDER_PARAM)
  @ApiQuery({ name: 'account_id',    required: true,  description: 'Your tenant / account ID',                example: '97106' })
  @ApiQuery({ name: 'client_id',     required: true,  description: 'OAuth client ID from the CRM app',        example: '1000.XXXXX' })
  @ApiQuery({ name: 'client_secret', required: true,  description: 'OAuth client secret from the CRM app',    example: 'abc123' })
  @ApiQuery({ name: 'redirect_uri',  required: false, description: 'Custom redirect URI (defaults to backend callback)', example: 'http://localhost:3000/api/oauth/callback/zoho' })
  @ApiResponse({ status: 200, description: 'Returns OAuth redirect URL' })
  @ApiResponse({ status: 400, description: 'Provider not supported or missing config' })
  async getAuthUrl(
    @Param('provider') provider: string,
    @Query('account_id') accountId: string,
    @Query('client_id') clientId: string,
    @Query('client_secret') clientSecret: string,
    @Query('redirect_uri') redirectUri: string,
  ) {
    const p = provider.toLowerCase();
    if (!CRM_PROVIDERS[p]) throw new BadRequestException(`Provider "${p}" is not supported.`);
    const config = CRM_PROVIDERS[p];
    if (config.authType === 'form') {
      return { authUrl: config.formUrl };
    }
    if (config.authType !== 'oauth') throw new BadRequestException(`Provider "${p}" does not use OAuth.`);
    if (!accountId) throw new BadRequestException('account_id is required.');


    const resolvedClientId     = clientId     || process.env[`${p.toUpperCase()}_CLIENT_ID`];
    const resolvedClientSecret = clientSecret || process.env[`${p.toUpperCase()}_CLIENT_SECRET`];
    if (!resolvedClientId || !resolvedClientSecret) {
      throw new BadRequestException('client_id and client_secret are required (pass in query or set env vars).');
    }

    const result = await this.oauthService.buildAuthUrl(p, accountId, {
      client_id: resolvedClientId,
      client_secret: resolvedClientSecret,
      ...(redirectUri ? { redirect_uri: redirectUri } : {}),
    });
    if (!result) return { success: false, message: 'Failed to generate auth URL.' };
    return { authUrl: result.authUrl };
  }

  @Post('crm/:provider/callback')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Exchange OAuth code for tokens', description: 'Frontend sends the code and state from the OAuth redirect URL. Backend exchanges for access/refresh tokens and stores in DB.' })
  @ApiParam(PROVIDER_PARAM)
  @ApiConsumes('application/json', 'application/x-www-form-urlencoded', 'multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      required: ['code', 'state'],
      properties: {
        code:             { type: 'string', description: 'Authorization code from OAuth redirect' },
        state:            { type: 'string', description: 'State token from OAuth redirect' },
        'accounts-server': { type: 'string', description: 'Zoho region server (optional)', example: 'https://accounts.zoho.in' },
        location:         { type: 'string', description: 'Zoho location (optional)', example: 'in' },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Tokens exchanged and stored' })
  @ApiResponse({ status: 400, description: 'Invalid code, expired state, or exchange failure' })
  async oauthExchange(
    @Param('provider') provider: string,
    @Body() body: Record<string, string>,
  ) {
    const p = provider.toLowerCase();
    if (!CRM_PROVIDERS[p]) throw new BadRequestException(`Provider "${p}" is not supported.`);
    const { code, state, ...rest } = body;
    if (!code || !state) throw new BadRequestException('Missing code or state');

    const stateData = await this.oauthService.getOAuthState(state);
    if (!stateData) throw new BadRequestException('Invalid or expired state. Try connecting again.');
    const accountId = stateData.accountId || 'unknown';

    this.logger.log(`OAuth callback for ${p}, accountId: ${accountId}`);

    const entity = await this.oauthService.handleOAuthCallback(p, code, state, accountId, rest);
    return {
      success:    true,
      provider:   p,
      accountId:  entity.accountId,
      apiDomain:  entity.apiDomain,
      tokenType:  entity.tokenType,
      expiresAt:  entity.expiresAt,
      createdAt:  entity.createdAt,
    };
  }

  @Post('crm/:provider/detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get connection detail for any CRM provider' })
  @ApiParam(PROVIDER_PARAM)
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  @ApiResponse({ status: 200, description: 'Provider connection detail' })
  @ApiResponse({ status: 400, description: 'Unsupported provider or missing user_id' })
  async providerDetail(
    @Param('provider') provider: string,
    @Body() body: Record<string, any>,
  ) {
    const p = provider.toLowerCase();
    if (!CRM_PROVIDERS[p]) throw new BadRequestException(`Provider "${p}" is not supported.`);
    return this.getProviderDetail(p, body);
  }

  @Post('bitrix_detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Bitrix24 — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  async bitrixDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('bitrix24', body); }

  @Post('zoho_detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Zoho — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  async zohoLegacyDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('zoho', body); }

  @Post('hubspot_detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'HubSpot — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  async hubspotLegacyDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('hubspot', body); }

  @Post('salesforce_detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Salesforce — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  async salesforceLegacyDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('salesforce', body); }

  @Post('pipedrive_detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Pipedrive — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  async pipedriveLegacyDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('pipedrive', body); }

  @Post('freshsales_detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Freshsales — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  async freshsalesLegacyDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('freshsales', body); }

  @Post('freshdesk_detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Freshdesk — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  async freshdeskLegacyDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('freshdesk', body); }

  @Post('odoo_detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Odoo — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  async odooLegacyDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('odoo', body); }

  @Post('kommo_detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Kommo — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  async kommoLegacyDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('kommo', body); }

  @Post('shopify_detail')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Shopify — get detail' })
  @ApiConsumes('application/x-www-form-urlencoded', 'application/json', 'multipart/form-data')
  @ApiBody(USER_ID_BODY)
  async shopifyLegacyDetail(@Body() body: Record<string, any>) { return this.getProviderDetail('shopify', body); }

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
    return this.tokenService.getAllDetail(userId);
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
    @Query() query: Record<string, string>,
  ) {
    const { code, state, ...rest } = query;
    const panelUrl = process.env.FRONTEND_URL || 'https://app.callerdesk.io/admin/';


    if (!code || !state) {
      return `<html><body><h2>&#x274C; ${provider} connection failed</h2><p>Missing code or state in callback URL.</p><script>setTimeout(function(){ window.location.href="${panelUrl}?provider=${provider}&connected=false"; }, 3000);</script></body></html>`;
    }
    const stateData = await this.oauthService.getOAuthState(state);
    if (!stateData) {
      return `<html><body><h2>&#x274C; ${provider} connection failed</h2><p>Your authorization session expired. Please click Connect again.</p><script>setTimeout(function(){ window.location.href="${panelUrl}?provider=${provider}&connected=false&error=expired_state"; }, 3000);</script></body></html>`;
    }
    const accountId = stateData.accountId || 'unknown';
    try {
      const entity = await this.oauthService.handleOAuthCallback(provider.toLowerCase(), code, state, accountId, rest);
      this.logger.log(`${provider} connected for accountId: ${entity.accountId} — tokens stored in DB`);
      return `<html><body><h2>&#x2705; ${provider} connected!</h2><p>Account: ${entity.accountId}</p><p>Tokens stored. Redirecting...</p><script>setTimeout(function(){ window.location.href="${panelUrl}?provider=${provider}&connected=true&accountId=${entity.accountId}"; }, 1500);</script></body></html>`;
    } catch (err: any) {
      this.logger.error(`OAuth callback failed for ${provider}: ${err.message}`);
      return `<html><body><h2>&#x274C; ${provider} connection failed</h2><p>${err.message}</p><script>setTimeout(function(){ window.location.href="${panelUrl}?provider=${provider}&connected=false&error=${encodeURIComponent(err.message)}"; }, 3000);</script></body></html>`;
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
  issueToken(
    @Body() body: { accountId?: string; account_id?: string },
    @Req() req: Request,
  ) {
    const internalKey = process.env.INTERNAL_API_KEY;
    if (internalKey) {
      const provided = (req.headers['x-internal-api-key'] as string) || '';
      if (provided !== internalKey) {
        throw new UnauthorizedException('Invalid or missing x-internal-api-key header');
      }
    } else if (process.env.NODE_ENV === 'production') {
      throw new UnauthorizedException('INTERNAL_API_KEY must be set in production');
    }
    const accountId = body.accountId || body.account_id;
    if (!accountId) throw new BadRequestException('accountId is required');
    const secret = process.env.JWT_SECRET;
    if (!secret) throw new Error('JWT_SECRET not set');
    const expiresIn = (process.env.JWT_EXPIRATION || '7d') as any;
    const token = jwt.sign({ sub: accountId, accountId }, secret, { expiresIn });
    return { token, accountId };
  }
}
