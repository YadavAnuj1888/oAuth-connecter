import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';

const ALG     = 'aes-256-gcm';
const IV_LEN  = 16;
const VERSION = 'v1';

@Injectable()
export class EncryptionService {
  private readonly key: Buffer;

  constructor() {
    const raw = process.env.ENCRYPTION_KEY || '';
    if (raw.length < 32) throw new Error('ENCRYPTION_KEY must be at least 32 chars in .env');
    this.key = Buffer.from(raw.slice(0, 32), 'utf8');
  }

  encrypt(plain: string): string {
    if (!plain) return plain;
    const iv     = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv(ALG, this.key, iv);
    const enc    = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
    const tag    = cipher.getAuthTag();

    return `${VERSION}:${iv.toString('hex')}:${tag.toString('hex')}:${enc.toString('hex')}`;
  }

  decrypt(stored: string): string {
    if (!stored || !stored.includes(':')) return stored;
    const parts = stored.split(':');

    const [ivHex, tagHex, ctHex] = parts.length === 4 ? parts.slice(1) : parts;
    const iv  = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const ct  = Buffer.from(ctHex, 'hex');
    const dec = crypto.createDecipheriv(ALG, this.key, iv);
    dec.setAuthTag(tag);
    return dec.update(ct).toString('utf8') + dec.final('utf8');
  }

  maskSensitiveValue(value: string | null): string | null {
    if (!value) return null;
    if (value.length <= 8) return '****';
    return value.substring(0, 4) + '****' + value.substring(value.length - 4);
  }
}
