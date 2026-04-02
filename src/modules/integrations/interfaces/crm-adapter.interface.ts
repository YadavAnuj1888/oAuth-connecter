export interface VerifyResult {
  userId:      string;
  accessToken: string | null;
  tokenType:   string | null;
  email?:      string | null;
  apiDomain?:  string | null;
}

export interface ConnectionDetail {
  id:            number;
  user_id:       string;
  api_domain:    string | null;
  access_token:  string | null;
  refresh_token: string | null;
  token_type:    string | null;
  email:         string | null;
  expires_at:    Date   | null;
  created_at:    Date;
  updated_at?:   Date;
}
