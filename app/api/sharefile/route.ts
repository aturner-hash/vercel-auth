import { NextRequest, NextResponse } from 'next/server';
import { webcrypto as nodeWebcrypto } from 'crypto';

// -------------------- Types & runtime shims --------------------
type CryptoLike = Crypto;
const cryptoImpl: CryptoLike =
  (globalThis.crypto as CryptoLike) ?? (nodeWebcrypto as unknown as CryptoLike);

// -------------------- Environment --------------------
const CLIENT_ID = process.env.SHAREFILE_CLIENT_ID!;
const CLIENT_SECRET = process.env.SHAREFILE_CLIENT_SECRET!;
const SUBDOMAIN = process.env.SHAREFILE_SUBDOMAIN || 'mtlawoffice';       // <-- your tenant (e.g., "mtlawoffice")
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || 'http://localhost:3000';

// -------------------- Helpers --------------------
function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

async function sha256(s: string): Promise<string> {
  const digest = await cryptoImpl.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return b64url(new Uint8Array(digest));
}

function randomUrlSafe(len = 32): string {
  const u = new Uint8Array(len);
  cryptoImpl.getRandomValues(u);
  return b64url(u);
}

interface SessionPayload {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  subdomain: string;
}

const sessionStore = new Map<string, SessionPayload>();

// -------------------- Route handler --------------------
export async function GET(req: NextRequest): Promise<NextResponse> {
  const url = new URL(req.url);
  const action = url.searchParams.get('action');

  if (action === 'start') {
    const returnTo = url.searchParams.get('return') || 'http://localhost:3000/oauth/callback';

    // PKCE
    const state = randomUrlSafe(16);
    const verifier = randomUrlSafe(64);
    const challenge = await sha256(verifier);

    // Tenant-pinned authorize base (prevents portal client substitution)
    const base = SUBDOMAIN
      ? `https://${SUBDOMAIN}.sharefile.com`
      : 'https://secure.sharefile.com';

    const redirectUri = `${req.nextUrl.origin}/api/sharefile?action=callback`;

    const auth = new URL(`${base}/oauth/authorize`);
    auth.searchParams.set('response_type', 'code');
    auth.searchParams.set('client_id', CLIENT_ID);
    auth.searchParams.set('redirect_uri', redirectUri);
    auth.searchParams.set('state', state);
    auth.searchParams.set('code_challenge', challenge);
    auth.searchParams.set('code_challenge_method', 'S256');

    // Hints to skip tenant entry even if identity forwards to Citrix OIDC
    if (SUBDOMAIN) {
      auth.searchParams.set('acr_values', `tenant:${SUBDOMAIN}`);
      auth.searchParams.set('subdomain', SUBDOMAIN);
    }

    const res = NextResponse.redirect(auth.toString());
    res.cookies.set('sf_oauth_state', state, { httpOnly: true, sameSite: 'lax', secure: true, path: '/' });
    res.cookies.set('sf_oauth_verifier', verifier, { httpOnly: true, sameSite: 'lax', secure: true, path: '/' });
    res.cookies.set('sf_return_to', returnTo, { httpOnly: true, sameSite: 'lax', secure: true, path: '/' });
    return res;
  }

  if (action === 'callback') {
    const q = new URL(req.url).searchParams;
    const code = q.get('code') || '';
    const state = q.get('state') || '';

    const cookieState = req.cookies.get('sf_oauth_state')?.value;
    const verifier = req.cookies.get('sf_oauth_verifier')?.value;
    const returnTo = req.cookies.get('sf_return_to')?.value;

    if (!state || state !== cookieState || !verifier || !returnTo) {
      return new NextResponse('Invalid or expired state', { status: 400 });
    }

    // Exchange authorization code for tokens
    const tokenRes = await fetch('https://secure.sharefile.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
        redirect_uri: `${req.nextUrl.origin}/api/sharefile?action=callback`,
        code_verifier: verifier,
      }),
    });

    if (!tokenRes.ok) {
      const txt = await tokenRes.text();
      return new NextResponse(
        `Token exchange failed: ${tokenRes.status}\n${txt}`,
        { status: 500, headers: { 'content-type': 'text/plain; charset=utf-8' } }
      );
    }

    const tok = await tokenRes.json() as {
      access_token: string;
      refresh_token?: string;
      expires_in?: number;
      subdomain?: string;
    };

    const sub = tok.subdomain || SUBDOMAIN || '';
    if (!sub) return new NextResponse('Missing subdomain in token/callback', { status: 400 });

    const sid = randomUrlSafe(24);
    sessionStore.set(sid, {
      access_token: tok.access_token,
      refresh_token: tok.refresh_token,
      expires_in: tok.expires_in,
      subdomain: sub,
    });

    const back = new URL(returnTo);
    back.searchParams.set('session', sid);

    const res = NextResponse.redirect(back.toString());
    res.cookies.delete('sf_oauth_state');
    res.cookies.delete('sf_oauth_verifier');
    res.cookies.delete('sf_return_to');
    return res;
  }

  if (action === 'session') {
    const id = url.searchParams.get('id') || '';
    const data = sessionStore.get(id);
    if (!data) return new NextResponse('Not found', { status: 404 });

    const res = NextResponse.json(data);
    res.headers.set('Access-Control-Allow-Origin', ALLOW_ORIGIN);
    res.headers.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.headers.set('Access-Control-Allow-Headers', 'Content-Type');
    return res;
  }

  return new NextResponse('Not Found', { status: 404 });
}

export async function OPTIONS(): Promise<NextResponse> {
  const res = new NextResponse(null, { status: 204 });
  res.headers.set('Access-Control-Allow-Origin', ALLOW_ORIGIN);
  res.headers.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.headers.set('Access-Control-Allow-Headers', 'Content-Type');
  return res;
}
