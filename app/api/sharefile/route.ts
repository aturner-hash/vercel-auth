import { NextRequest, NextResponse } from 'next/server';
import { webcrypto as nodeWebcrypto } from 'crypto';

// Use Web Crypto that works in Node runtimes
const cryptoImpl: Crypto = (globalThis.crypto as Crypto) ?? (nodeWebcrypto as unknown as Crypto);

const CLIENT_ID = process.env.SHAREFILE_CLIENT_ID!;
const CLIENT_SECRET = process.env.SHAREFILE_CLIENT_SECRET!;
const CONTROL_PLANE = process.env.SHAREFILE_CONTROL_PLANE || 'sharefile.com';
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || 'http://localhost:3000';

const sessionStore = new Map<string, any>();

function b64url(bytes: Uint8Array) {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
async function sha256(s: string) {
  const hash = await cryptoImpl.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return b64url(new Uint8Array(hash));
}
function randomString(len = 32) {
  const arr = new Uint8Array(len);
  cryptoImpl.getRandomValues(arr);
  return b64url(arr);
}

export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const action = url.searchParams.get('action');

  if (action === 'start') {
    const returnTo = url.searchParams.get('return') || 'http://localhost:3000/oauth/callback';

    // Build PKCE
    const state = randomString(16);
    const verifier = randomString(64);
    const challenge = await sha256(verifier);

    // Build authorize URL
    const redirectUri = `${req.nextUrl.origin}/api/sharefile?action=callback`;
    const auth = new URL('https://secure.sharefile.com/oauth/authorize');
    auth.searchParams.set('response_type', 'code');
    auth.searchParams.set('client_id', CLIENT_ID);
    auth.searchParams.set('redirect_uri', redirectUri);
    auth.searchParams.set('state', state);
    auth.searchParams.set('code_challenge', challenge);
    auth.searchParams.set('code_challenge_method', 'S256');

    const res = NextResponse.redirect(auth.toString());
    // Store PKCE + return in httpOnly cookies so we survive cold starts
    res.cookies.set('sf_oauth_state', state,   { httpOnly: true, sameSite: 'lax', secure: true, path: '/' });
    res.cookies.set('sf_oauth_verifier', verifier, { httpOnly: true, sameSite: 'lax', secure: true, path: '/' });
    res.cookies.set('sf_return_to', returnTo,  { httpOnly: true, sameSite: 'lax', secure: true, path: '/' });
    return res;
  }

  if (action === 'callback') {
    const code = url.searchParams.get('code') || '';
    const state = url.searchParams.get('state') || '';

    const cookieState    = req.cookies.get('sf_oauth_state')?.value;
    const verifierCookie = req.cookies.get('sf_oauth_verifier')?.value;
    const returnToCookie = req.cookies.get('sf_return_to')?.value;

    if (!state || state !== cookieState || !verifierCookie || !returnToCookie) {
      return new NextResponse('Invalid or expired state', { status: 400 });
    }

    // Exchange code for tokens
    const tokenRes = await fetch('https://secure.sharefile.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
        redirect_uri: `${req.nextUrl.origin}/api/sharefile?action=callback`,
        code_verifier: verifierCookie,
      }),
    });
    if (!tokenRes.ok) {
      const txt = await tokenRes.text();
      return new NextResponse(`Token exchange failed: ${tokenRes.status} ${txt}`, { status: 500 });
    }
    const tok = await tokenRes.json();

    // Ensure subdomain is present (or fallback to fixed-tenant if configured)
    const sub = tok.subdomain || process.env.SHAREFILE_SUBDOMAIN || '';
    if (!sub) return new NextResponse('Missing subdomain in token/callback', { status: 400 });

    // Create one-time session payload including subdomain
    const sessionId = randomString(24);
    sessionStore.set(sessionId, {
      access_token: tok.access_token,
      refresh_token: tok.refresh_token,
      token_type: tok.token_type || 'Bearer',
      expires_in: tok.expires_in,
      subdomain: sub,
      obtained_at: Date.now(),
      controlPlane: CONTROL_PLANE,
    });

    // Redirect back to local site with session id
    const back = new URL(returnToCookie);
    back.searchParams.set('session', sessionId);
    const res = NextResponse.redirect(back.toString());
    // Clear cookies
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

export async function OPTIONS() {
  const res = new NextResponse(null, { status: 204 });
  res.headers.set('Access-Control-Allow-Origin', process.env.ALLOW_ORIGIN || 'http://localhost:3000');
  res.headers.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.headers.set('Access-Control-Allow-Headers', 'Content-Type');
  return res;
}
