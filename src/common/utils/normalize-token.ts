export interface NormalizedToken {
  accessToken:  string;
  refreshToken: string | null;
  tokenType:    string;
  expiresAt:    Date | null;
  rawUserId:    string | null;
}

export function normalizeToken(raw: Record<string, any>): NormalizedToken {
  const expiresInRaw = raw.expires_in != null ? parseInt(raw.expires_in, 10) : null;
  const expiresIn    = expiresInRaw !== null && !isNaN(expiresInRaw) && expiresInRaw > 0
    ? expiresInRaw
    : null;

  return {
    accessToken:  raw.access_token  || '',
    refreshToken: raw.refresh_token || null,
    tokenType:    (raw.token_type   || 'bearer').toLowerCase(),
    expiresAt:    expiresIn != null ? new Date(Date.now() + expiresIn * 1000) : null,
    rawUserId:    String(raw.hub_id || raw.user_id || raw.userId || raw.id || '') || null,
  };
}
