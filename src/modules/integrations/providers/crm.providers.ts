import { BadRequestException } from '@nestjs/common';

export type AuthType   = 'oauth' | 'credentials' | 'form';
export type AuthMethod = 'body'  | 'basic';

export interface FormProviderConfig {
  authType: 'form';
  formUrl:  string;
  metadata: ProviderMetadata;
}

export interface ProviderMetadata { displayName: string; logo: string; color: string; }

export interface OAuthProviderConfig {
  authType:              'oauth';
  authUrl:               string;
  tokenUrl:              string;
  refreshUrl?:           string;
  apiDomain:             string;
  scopes:                string[];
  scopeSeparator:        ',' | ' ';
  redirectUrl:           string;
  authMethod:            AuthMethod;
  pkce?:                 boolean;
  userIdPath?:           string;
  promptConsent?:        boolean;
  dynamicAuthUrl?:       boolean;
  dynamicUrl?:           boolean;
  dynamicRegion?:        boolean;
  tokenContentType?:     'json' | 'form';
  rotatesRefreshToken?:  boolean;
  metadata:              ProviderMetadata;
}

export interface CredentialProviderConfig {
  authType: 'credentials'; apiDomain?: string; requiredFields: string[];
  metadata: ProviderMetadata;
}

export type ProviderConfig = OAuthProviderConfig | CredentialProviderConfig | FormProviderConfig;

export const CRM_PROVIDERS: Record<string, ProviderConfig> = {

  zoho: {
    authType: 'oauth', authMethod: 'body', pkce: false,

    authUrl:    'https://accounts.zoho.{region}/oauth/v2/auth',
    tokenUrl:   'https://accounts.zoho.{region}/oauth/v2/token',
    refreshUrl: 'https://accounts.zoho.{region}/oauth/v2/token',
    apiDomain:  'https://www.zohoapis.{region}/crm/v3/',
    scopeSeparator: ',',
    redirectUrl: process.env.ZOHO_REDIRECT_URL || 'https://app.callerdesk.io/admin/zoho-data',
    scopes: ['PhoneBridge.call.log','PhoneBridge.zohoone.search'],
    promptConsent: true,
    dynamicRegion: true,
    userIdPath: 'user_id',
    metadata: { displayName: 'Zoho', logo: 'https://cdn.simpleicons.org/zoho/E42527', color: '#E42527' },
  },

  hubspot: {
    authType: 'oauth', authMethod: 'body', pkce: false,
    authUrl:    'https://app.hubspot.com/oauth/authorize',
    tokenUrl:   'https://api.hubapi.com/oauth/v1/token',
    refreshUrl: 'https://api.hubapi.com/oauth/v1/token',
    apiDomain: 'https://api.hubapi.com/', scopeSeparator: ' ',
    redirectUrl: process.env.HUBSPOT_REDIRECT_URL || 'https://app.callerdesk.io/admin/hubspot-data',
    scopes: ['crm.objects.contacts.read','crm.objects.contacts.write','crm.objects.deals.read','crm.objects.deals.write','crm.objects.calls.write','tickets'],
    userIdPath: 'hub_id',
    metadata: { displayName: 'HubSpot', logo: 'https://cdn.simpleicons.org/hubspot/FF7A59', color: '#FF7A59' },
  },

  salesforce: {
    authType: 'oauth', authMethod: 'body', pkce: false,
    authUrl:    'https://login.salesforce.com/services/oauth2/authorize',
    tokenUrl:   'https://login.salesforce.com/services/oauth2/token',
    refreshUrl: 'https://login.salesforce.com/services/oauth2/token',
    apiDomain: 'https://login.salesforce.com/services/data/v59.0/', scopeSeparator: ' ',
    redirectUrl: process.env.SALESFORCE_REDIRECT_URL || 'https://app.callerdesk.io/admin/salesforce-data',
    scopes: ['api','refresh_token','offline_access'],
    userIdPath: 'id',
    metadata: { displayName: 'Salesforce', logo: '', color: '#00A1E0' },
  },

  pipedrive: {
    authType: 'oauth', authMethod: 'basic', pkce: false,
    authUrl:    'https://oauth.pipedrive.com/oauth/authorize',
    tokenUrl:   'https://oauth.pipedrive.com/oauth/token',
    refreshUrl: 'https://oauth.pipedrive.com/oauth/token',
    apiDomain: 'https://api.pipedrive.com/v1/', scopeSeparator: ' ', scopes: [],
    redirectUrl: process.env.PIPEDRIVE_REDIRECT_URL || 'https://app.callerdesk.io/admin/pipedrive-data',
    rotatesRefreshToken: true,
    userIdPath: 'data.id',
    metadata: { displayName: 'Pipedrive', logo: '', color: '#1A1A2E' },
  },

  kommo: {
    authType: 'credentials', requiredFields: ['subDomain','token'],
    metadata: { displayName: 'Kommo', logo: '', color: '#339AF0' },
  },

  bitrix24: {
    authType: 'credentials', requiredFields: ['bitrixUrl','clientId','clientSecret'],
    metadata: { displayName: 'Bitrix24', logo: '', color: '#E53935' },
  },

  shopify: {
    authType: 'credentials', requiredFields: ['clientId','clientSecret','subDomain'],
    metadata: { displayName: 'Shopify', logo: 'https://cdn.simpleicons.org/shopify/96BF48', color: '#96BF48' },
  },

  odoo: {
    authType: 'credentials', requiredFields: ['odooUrl','databaseName','userEmail','apiKey'],
    metadata: { displayName: 'Odoo', logo: 'https://cdn.simpleicons.org/odoo/875A7B', color: '#875A7B' },
  },

  examplecrm2: {
    authType:       'credentials',
    requiredFields: ['apiKey', 'subdomain'],
    metadata: { displayName: 'ExampleCRM2', logo: '', color: '#FF5733' },
  },

  freshdesk: {
    authType: 'credentials', requiredFields: ['bundleAlias','apiKey'],
    metadata: { displayName: 'Freshdesk', logo: '', color: '#27B4AC' },
  },

  examplecrm: {
    authType:     'oauth',
    authMethod:   'body',
    pkce:         false,
    authUrl:      'https://examplecrm.com/oauth/authorize',
    tokenUrl:     'https://examplecrm.com/oauth/token',
    refreshUrl:   'https://examplecrm.com/oauth/token',
    apiDomain:    'https://api.examplecrm.com/',
    scopes:       ['contacts.read', 'contacts.write'],
    scopeSeparator: ' ',
    redirectUrl:  process.env.EXAMPLECRM_REDIRECT_URL || 'https://app.callerdesk.io/admin/examplecrm-data',
    userIdPath:   'user_id',
    metadata: { displayName: 'ExampleCRM', logo: '', color: '#6C63FF' },
  },

  faveo: {
    authType: 'oauth', authMethod: 'body', pkce: false,
    authUrl:    'https://testaccount.faveocloud.com/oauth/authorize',
    tokenUrl:   'https://testaccount.faveocloud.com/oauth/token',
    refreshUrl: 'https://testaccount.faveocloud.com/oauth/token',
    apiDomain: 'https://testaccount.faveocloud.com/', scopeSeparator: ' ',
    redirectUrl: process.env.FAVEO_REDIRECT_URL || 'https://app.callerdesk.io/admin/faveo-data/',
    scopes: ['*'],
    metadata: { displayName: 'Faveo', logo: '', color: '#0078D4' },
  },

  borgerp: {
    authType: 'form',
    formUrl:  'https://docs.google.com/forms/d/e/1FAIpQLSfYfDN8s-b9AoVvlONmJ0BBC3PrUjibo5jJvb_n-xKTcekOMw/viewform',
    metadata: { displayName: 'Borg ERP', logo: '', color: '#6A1B9A' },
  },

  telecrm: {
    authType: 'form',
    formUrl:  'https://docs.google.com/forms/d/e/1FAIpQLSc8qE-r5NBHIc11Zrm3wH4YEjEblIzmrl855oe4A_7CpOktRA/viewform',
    metadata: { displayName: 'TeleCRM', logo: '', color: '#1E88E5' },
  },

  pabbly: {
    authType: 'form',
    formUrl:  'https://accounts.pabbly.com/login',
    metadata: { displayName: 'Pabbly', logo: '', color: '#FF6B35' },
  },

  superleap: {
    authType: 'form',
    formUrl:  'https://docs.google.com/forms/d/e/1FAIpQLSeW6KCYXO6eJsQY6U82J31m0zukZdThR7niX_TKoitn-NHi-w/viewform',
    metadata: { displayName: 'SuperLeap', logo: '', color: '#4285F4' },
  },

  freshsales: {
    authType: 'oauth', authMethod: 'basic', pkce: false,
    authUrl:    'https://{subdomain}/org/oauth/v2/authorize',
    tokenUrl:   'https://{subdomain}/org/oauth/v2/token',
    refreshUrl: 'https://{subdomain}/org/oauth/v2/token',
    apiDomain:  'https://{subdomain}/',
    scopeSeparator: ' ',
    scopes: ['contact.view', 'contact.manage'],
    redirectUrl: process.env.FRESHSALES_REDIRECT_URL || 'https://app.callerdesk.io/admin/freshsales-data',
    dynamicAuthUrl: true,
    userIdPath: 'id',
    metadata: { displayName: 'Freshsales', logo: '', color: '#0CA560' },
  },
};

export function getProviderConfig(provider: string): ProviderConfig {
  const config = CRM_PROVIDERS[provider.toLowerCase()];
  if (!config) throw new BadRequestException(`Provider "${provider}" is not supported.`);
  return config;
}
