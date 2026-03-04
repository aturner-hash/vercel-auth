// api/sharefile.ts
import type { VercelRequest, VercelResponse } from '@vercel/node';
import crypto from 'crypto';

// Optional: Upstash Redis (serverless-friendly)
let redis: { get: (k: string) => Promise<string | null>; setex: (k: string, ttl: number, v: string) => Promise<void>; del: (k: string) => Promise<void> } | null = null;
try {
  // Lazy import only if env present
  if (process.env.REDIS_URL && process.env.REDIS_TOKEN) {
    const { Redis } = await import('@upstash/redis');
    const client = new Redis({ url: process.env.REDIS_URL!, token: process.env.REDIS_TOKEN! });
    redis = {
      get: (k) => client.get<string>(k),
      setex: (k, ttl, v) => client.set(k, v, { ex: ttl }),
      del: (k) => client.del(k).then(() => {}),
    };
  }
} catch {
  // ignore; will fall back to memory
}

// Fallback in-memory store (dev only; not durable across cold starts)
const mem = new Map<string, { v: string; exp: number }>();
const nowSec = () => Math.floor(Date.now() / 1000);
async function kvSetEx(key: string, seconds: number, value: string) {
  if (redis) return redis.setex(key, seconds, value);
  mem.set(key, { v: value, exp: nowSec() + seconds });
}
async function kvGet(key: string) {
  if (redis) return (await redis.get(key)) ?? null;
  const e = mem.get(key);
  if (!e) return null;
  if (nowSec() > e.exp) { mem.delete(key); return null; }
  return e.v;
}
async function kvDel(key: string) {
  if (redis) return redis.del(key);
  mem.delete(key);
}

function b64url(buf: Buffer) {
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function randomB64Url(size = 32) {
  return b64url(crypto.randomBytes(size));
}

function sha256B64Url(input: string) {
  return b64url(crypto.createHash('sha256').update(input).digest());
}

const CLIENT_ID = process.env.SHAREFILE_CLIENT_ID!;
const CLIENT_SECRET = process.env.SHAREFILE_CLIENT_SECRET!;
const REDIRECT_URI = process.env.SHAREFILE_REDIRECT_URI!;
const APP_DEEP_LINK = process.env.APP_DEEP_LINK; // optional

// TTLs (seconds)
const STATE_TTL = 5 * 60;
const SESSION_TTL = 5 * 60;

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const action = String(req.query.action || '').toLowerCase();

  if (req.method === 'POST' && action === 'start') {
    // 1) Generate PKCE + state and return auth URL for the client to open
    try {
      const code_verifier = randomB64Url(32);
      const code_challenge = sha256B64Url(code_verifier);
      const state = randomB64Url(16);

      await kvSetEx(`sf:state:${state}`, STATE_TTL, JSON.stringify({ code_verifier }));

      const params = new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        state,
        code_challenge: code_challenge,
        code_challenge_method: 'S256',
      });

      const authUrl = `https://secure.sharefile.com/oauth/authorize?${params.toString()}`;
      // Starts at secure.sharefile.com; user authenticates and ShareFile redirects back to REDIRECT_URI (your server). [1](https://support.okta.com/help/s/article/Configure-OAuth-and-RESTShareFile-Integration?language=en_US)
      return res.status(200).json({ authUrl, state });
    } catch (e: any) {
      return res.status(500).json({ error: 'start_failed', detail: String(e?.message ?? e) });
    }
  }

  if (req.method === 'GET' && action === 'callback') {
    // 2) Handle ShareFile redirect ?code=...&state=...&subdomain=...
    try {
      const code = String(req.query.code || '');
      const state = String(req.query.state || '');
      const subdomain = String(req.query.subdomain || '');

      if (!code || !state || !subdomain) {
        return res.status(400).send('Missing code/state/subdomain');
      }

      const stashRaw = await kvGet(`sf:state:${state}`);
      if (!stashRaw) return res.status(400).send('Invalid or expired state');
      await kvDel(`sf:state:${state}`);

      const { code_verifier } = JSON.parse(stashRaw) as { code_verifier: string };

      // Token exchange must be on the tenant host: https://<subdomain>.sharefile.com/oauth/token (or .sharefile.eu) [2](https://docs.cloud-elements.com/home/sharefile-authenticate)
      const tokenUrl = `https://${subdomain}.sharefile.com/oauth/token`;
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
        code,
        code_verifier,
      }).toString();

      const r = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      });

      const json = await r.json();
      if (!r.ok) {
        return res.status(r.status).send(`<pre>Token exchange failed:\n${JSON.stringify(json, null, 2)}</pre>`);
      }

      const session = randomB64Url(16);
      const bundle = { ...json, subdomain };
      await kvSetEx(`sf:session:${session}`, SESSION_TTL, JSON.stringify(bundle));

      // Hand back to app: either deep link or show session code
      if (APP_DEEP_LINK) {
        const url = `${APP_DEEP_LINK}?session=${encodeURIComponent(session)}`;
        res.setHeader('Content-Type', 'text/html');
        return res.status(200).send(
          `<!doctype html><meta name="viewport" content="width=device-width, initial-scale=1">
           <p>Returning to the app…</p>
           <script>location.replace(${JSON.stringify(url)});</script>`
        );
      } else {
        res.setHeader('Content-Type', 'text/html');
        return res.status(200).send(
          `<!doctype html><meta name="viewport" content="width=device-width, initial-scale=1">
           <h3>ShareFile authentication complete</h3>
           <p>Copy this one‑time session code into your app:</p>
           <pre style="font-size:16px">${session}</pre>
           <small>Valid for ${SESSION_TTL/60} minutes.</small>`
        );
      }
    } catch (e: any) {
      return res.status(500).send(`<pre>${String(e?.message ?? e)}</pre>`);
    }
  }

  if (req.method === 'GET' && action === 'session') {
    // 3) Return and invalidate the one‑time token bundle
    const id = String(req.query.id || '');
    if (!id) return res.status(400).json({ error: 'missing_id' });
    const raw = await kvGet(`sf:session:${id}`);
    if (!raw) return res.status(404).json({ error: 'invalid_or_expired' });
    await kvDel(`sf:session:${id}`);
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json(JSON.parse(raw));
  }

  return res.status(404).json({ error: 'not_found' });
}