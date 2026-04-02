import { IsString, IsOptional, IsUrl, IsEmail } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ConnectOAuthDto {
  @ApiProperty({ required: false, example: 'my_client_id', description: 'Override the client_id from .env' })
  @IsOptional() @IsString() client_id?: string;

  @ApiProperty({ required: false, example: 'https://app.example.com/admin/hubspot-data', description: 'Override the redirect URI from config' })
  @IsOptional() @IsString() redirect_uri?: string;

  @ApiProperty({ required: false, example: 'myshop', description: 'Shopify shop subdomain' })
  @IsOptional() @IsString() shop?: string;

  @ApiProperty({ required: false, example: 'mycompany.freshsales.io', description: 'Required for Freshsales — subdomain of the account' })
  @IsOptional() @IsString() subdomain?: string;
}

export class ConnectCredentialsDto {
  @ApiProperty({ required: false, example: 'https://myodoo.com', description: 'Odoo instance URL' })
  @IsOptional() @IsUrl() odooUrl?: string;

  @ApiProperty({ required: false, example: 'mydb', description: 'Odoo database name' })
  @IsOptional() @IsString() databaseName?: string;

  @ApiProperty({ required: false, example: 'admin@mycompany.com', description: 'Odoo login email' })
  @IsOptional() @IsEmail() userEmail?: string;

  @ApiProperty({ required: false, example: 'abc123xyz', description: 'API key for Freshdesk / Odoo' })
  @IsOptional() @IsString() apiKey?: string;

  @ApiProperty({ required: false, example: 'https://mycompany.bitrix24.com', description: 'Bitrix24 account URL' })
  @IsOptional() @IsUrl() bitrixUrl?: string;

  @ApiProperty({ required: false, example: 'my_client_id', description: 'OAuth client ID (Bitrix24, Shopify)' })
  @IsOptional() @IsString() clientId?: string;

  @ApiProperty({ required: false, example: 'my_client_secret', description: 'OAuth client secret (Bitrix24, Shopify)' })
  @IsOptional() @IsString() clientSecret?: string;

  @ApiProperty({ required: false, example: 'mycompany', description: 'Freshdesk subdomain (bundleAlias)' })
  @IsOptional() @IsString() bundleAlias?: string;

  @ApiProperty({ required: false, example: 'mycompany', description: 'Kommo subdomain' })
  @IsOptional() @IsString() subDomain?: string;

  @ApiProperty({ required: false, example: 'eyJ...', description: 'Pre-issued access token (Kommo, Shopify)' })
  @IsOptional() @IsString() token?: string;

  @ApiProperty({ required: false, example: 'https://login.salesforce.com', description: 'Salesforce base URL' })
  @IsOptional() @IsUrl() baseUrl?: string;
}

export class OAuthCallbackDto {
  @ApiProperty({ example: 'authorization_code_here', description: 'Authorization code returned by the OAuth provider' })
  @IsString() code: string;

  @ApiProperty({ example: 'state_token_here', description: 'State token generated during connect — verified against Redis' })
  @IsString() state: string;
}

export class ConnectRequestDto {
  @ApiProperty({ required: false, example: 'my_client_id' })
  @IsOptional() @IsString() client_id?: string;

  @ApiProperty({ required: false, example: 'https://app.example.com/admin/hubspot-data' })
  @IsOptional() @IsString() redirect_uri?: string;

  @ApiProperty({ required: false, example: 'myshop' })
  @IsOptional() @IsString() shop?: string;

  @ApiProperty({ required: false, example: 'mycompany.freshsales.io', description: 'Required for Freshsales' })
  @IsOptional() @IsString() subdomain?: string;

  @ApiProperty({ required: false, example: 'https://myodoo.com' })
  @IsOptional() @IsUrl() odooUrl?: string;

  @ApiProperty({ required: false, example: 'mydb' })
  @IsOptional() @IsString() databaseName?: string;

  @ApiProperty({ required: false, example: 'admin@mycompany.com' })
  @IsOptional() @IsEmail() userEmail?: string;

  @ApiProperty({ required: false, example: 'abc123xyz' })
  @IsOptional() @IsString() apiKey?: string;

  @ApiProperty({ required: false, example: 'https://mycompany.bitrix24.com' })
  @IsOptional() @IsUrl() bitrixUrl?: string;

  @ApiProperty({ required: false, example: 'my_client_id' })
  @IsOptional() @IsString() clientId?: string;

  @ApiProperty({ required: false, example: 'my_client_secret' })
  @IsOptional() @IsString() clientSecret?: string;

  @ApiProperty({ required: false, example: 'mycompany' })
  @IsOptional() @IsString() bundleAlias?: string;

  @ApiProperty({ required: false, example: 'mycompany' })
  @IsOptional() @IsString() subDomain?: string;

  @ApiProperty({ required: false, example: 'eyJ...' })
  @IsOptional() @IsString() token?: string;

  @ApiProperty({ required: false, example: 'https://login.salesforce.com' })
  @IsOptional() @IsUrl() baseUrl?: string;
}

export class UserIdDto {
  @ApiProperty({ example: '97106', description: 'Account / tenant ID' })
  user_id: string;
}
