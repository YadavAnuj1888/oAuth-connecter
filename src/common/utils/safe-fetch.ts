import { BadGatewayException } from '@nestjs/common';

interface SafeFetchOptions extends RequestInit {
  timeoutMs?:    number;
  retries?:      number;
  retryDelayMs?: number;
}

export async function safeFetch(url: string, opts: SafeFetchOptions = {}): Promise<Response> {
  const { timeoutMs = 10000, retries = 3, retryDelayMs = 500, ...fetchOpts } = opts;
  let lastError: Error = new Error('Unknown');

  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer      = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { ...fetchOpts, signal: controller.signal });
      clearTimeout(timer);

      if (res.status === 429 && attempt < retries) {
        const retryAfter = parseInt(res.headers.get('retry-after') || '0', 10);
        const wait = retryAfter > 0
          ? retryAfter * 1000
          : backoffWithJitter(retryDelayMs, attempt);
        await sleep(wait);
        continue;
      }

      if (res.status >= 400 && res.status < 500 && res.status !== 408) {
        return res;
      }
      if (res.status >= 500 && attempt < retries) {
        await sleep(backoffWithJitter(retryDelayMs, attempt));
        continue;
      }
      return res;
    } catch (err: any) {
      clearTimeout(timer);
      lastError = err;
      if (attempt < retries) await sleep(backoffWithJitter(retryDelayMs, attempt));
    }
  }
  throw new BadGatewayException(`CRM API unreachable after ${retries} retries: ${lastError.message}`);
}

function backoffWithJitter(baseMs: number, attempt: number): number {
  const exponential = baseMs * Math.pow(2, attempt);
  const capped = Math.min(exponential, 30_000);
  const jitter = Math.floor(Math.random() * capped * 0.3);
  return capped + jitter;
}

function sleep(ms: number) { return new Promise((r) => setTimeout(r, ms)); }
