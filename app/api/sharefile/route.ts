import { NextRequest, NextResponse } from 'next/server';
import { webcrypto as nodeWebcrypto } from 'crypto';

// ---- Types ----
interface SessionPayload {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  subdomain: string;
}

type CryptoLike = Crypto;

// ---- Web Crypto (Node + Edge safe) ----
const cryptoImpl: CryptoLike =
  (globalThis.crypto as CryptoLike) ?? (nodeWebcrypto as unknown as CryptoLike);

// ---- Env ----
const CLIENT_ID = process.env.SHAREFILE_CLIENT_ID!;
const CLIENT_SECRET = process.env.SHAREFILE_CLIENT_SECRET!;
const SUB = process.env.SHAREFILE_SUBDOMAIN || '';
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || 'http://localhost:3000';

// ---- Helpers ----
function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

async function sha256(s: string): Promise<string> {
  const digest = await cryptoImpl.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(s)
  );
  return b64url(new Uint8Array(digest));
}

function randomUrlSafe(len = 32): string {
  const u = new Uint8Array(len);
  cryptoImpl.getRandomValues(u);
  return b64url(u);
}

// simple in-memory store (use KV/Redis in prod)
const sessionStore = new Map<string, SessionPayload>();

export async function GET(req: NextRequest): Promise<NextResponse> {
  const url = new URL(req.url);
  const action = url.searchParams.get('action');

  if (action === 'start') {
    const returnTo =
      url.searchParams.get('return') || 'http://localhost:3000/oauth/callback';

    // Build PKCE
    const state = randomUrlSafe(16);
    const verifier = randomUrlSafe(64);
    const challenge = await sha256(verifier);

    // Tenant-pinned authorize base
    const base = SUB ? `https://${SUB}.sharefile.com` : 'https://secure.sharefile.com';
    const redirectUri = `${req.nextUrl.origin}/api/sharefile?action=callback`;

    const auth = new URL(`${base}/oauth/authorize`);
    auth.searchParams.set('response_type', 'code');
    auth.searchParams.set('client_id', CLIENT_ID);
    auth.searchParams.set('redirect_uri', redirectUri);
    auth.searchParams.set('state', state);
    auth.searchParams.set('code_challenge', challenge);
    auth.searchParams.set('code_challenge_method', 'S256');

    // Supply both hints to avoid tenant discovery / portal client substitution
    if (SUB) {
      auth.searchParams.set('acr_values', `tenant:${SUB}`);
      auth.searchParams.set('subdomain', SUB);
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

    // Exchange code
    const tokenRes = await fetch('https');
