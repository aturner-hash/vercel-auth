import { NextRequest, NextResponse } from 'next/server';
import { webcrypto as nodeWebcrypto } from 'crypto';

// ---- Web Crypto (Node serverless safe) ----
const cryptoImpl: Crypto = (globalThis.crypto as Crypto) ?? (nodeWebcrypto as unknown as Crypto);

// ---- Env ----
const CLIENT_ID = process.env.SHAREFILE_CLIENT_ID!;
const CLIENT_SECRET = process.env.SHAREFILE_CLIENT_SECRET!;
const CONTROL_PLANE = process.env.SHAREFILE_CONTROL_PLANE || 'sharefile.com';
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || 'http://localhost:3000';
const AUTH_TRACE = process.env.AUTH_TRACE === '1'; // turn on HTML trace mode

// ---- Ephemeral session store (dev). Use KV/Redis in prod. ----
const sessionStore = new Map<string, any>();

// ---- Helpers ----
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
function htmlEscape(s: string) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const action = url.searchParams.get('action');
  const debug = url.searchParams.get('debug') === '1';

  if (action === 'start') {
    const returnTo = url.searchParams.get('return') || 'http://localhost:3000/oauth/callback';

    // Build PKCE
    const state = randomString(16);
    const verifier = randomString(64);
    const challenge = await sha256(verifier);

    // Build authorize URL (classic ShareFile OAuth)
    const redirectUri = `${req.nextUrl.origin}/api/sharefile?action=callback`;
    const auth = new URL('https://secure.sharefile.com/oauth/authorize');
    auth.searchParams.set('response_type', 'code');
    auth.searchParams.set('client_id', CLIENT_ID);
    auth.searchParams.set('redirect_uri', redirectUri);
    auth.searchParams.set('state', state);
    auth.searchParams.set('code_challenge', challenge);
    auth.searchParams.set('code_challenge_method', 'S256');

    // Console trace
    console.log('[auth.start] AUTH URL =>', auth.toString());

    // If trace mode or debug=1, render an HTML page with a clickable link
    if (AUTH_TRACE || debug) {
      const body = `<!doctype html>
<html><head><meta charset="utf-8"><title>ShareFile Auth Trace</title></head>
<body style="font-family: system-ui, -apple-system, Segoe UI, Arial; padding:16px">
  <h1>ShareFile Auth Trace</h1>
  <p><strong>Authorize endpoint:</strong></p>
  <p><a href="${htmlEscape(auth.toString())}">${htmlEscape(auth.toString())}</a></p>
  <hr/>
  <h2>Parameters</h2>
  <pre>${htmlEscape(JSON.stringify({
    response_type: 'code',
    client_id: CLIENT_ID ? CLIENT_ID.slice(0,6) + '…' : '(missing)',
    redirect_uri: redirectUri,
    state,
    code_challenge: challenge.slice(0,8) + '…',
    code_challenge_method: 'S256'
  }, null, 2))}</pre>
  <h2>Return URL (after callback)</h2>
  <pre>${htmlEscape(returnTo)}</pre>
  <p style="color:#555">TRACE mode is enabled via AUTH_TRACE=1 or debug=1 query.</p>
</body></html>`;
      const res = new NextResponse(body, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' }});
      // Stash cookies so clicking the link still works
      res.cookies.set('sf_oauth_state', state, { httpOnly: true, sameSite: 'lax', secure: true, path: '/' });
      res.cookies.set('sf_oauth_verifier', verifier, { httpOnly: true, sameSite: 'lax', secure: true, path: '/' });
      res.cookies.set('sf_return_to', returnTo, { httpOnly: true, sameSite: 'lax', secure: true, path: '/' });
      return res;
    }

    // Normal redirect flow
    const res = NextResponse.redirect(auth.toString());
    res.cookies.set('sf_oauth_state', state,   { httpOnly: true, sameSite: 'lax', secure: true, path: '/' });
    res.cookies.set('sf_oauth_verifier', verifier, { httpOnly: true, sameSite: 'lax', secure: true, path: '/' });
    res.cookies.set('sf_return_to', returnTo,  { httpOnly: true, sameSite: 'lax', secure: true, path: '/' });
    return res;
  }

  if (action === 'callback') {
    const code = url.searchParams.get('code') || '';
    const state = url.searchParams.get('state') || '';
    const subdomainHint = url.searchParams.get('subdomain') || '';
    const apicp = url.searchParams.get('apicp') || '';
    const appcp = url.searchParams.get('appcp') || '';

    // Console trace incoming params (mask code)
    console.log('[auth.callback] query', {
      code: code ? code.slice(0,6) + '…' : '(missing)',
      state,
      subdomain: subdomainHint,
      apicp,
      appcp,
    });

    const cookieState    = req.cookies.get('sf_oauth_state')?.value;
    const verifierCookie = req.cookies.get('sf_oauth_verifier')?.value;
    const returnToCookie = req.cookies.get('sf_return_to')?.value;

    if (!state || state !== cookieState || !verifierCookie || !returnToCookie) {
      console.error('[auth.callback] state/verifier missing or mismatch', { state, cookieState, hasVerifier: !!verifierCookie, hasReturn: !!returnToCookie });
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

    console.log('[auth.callback] tokenRes.status', tokenRes.status);

    if (!tokenRes.ok) {
      const txt = await tokenRes.text();
      console.error('[auth.callback] token exchange failed', tokenRes.status, txt.slice(0, 500));
      if (AUTH_TRACE) {
        return new NextResponse(`Token exchange failed: ${tokenRes.status}
${txt}`, { status: 500, headers: { 'content-type': 'text/plain; charset=utf-8' }});
      }
      return new NextResponse(`Token exchange failed: ${tokenRes.status}`, { status: 500 });
    }

    const tok = await tokenRes.json();
    const sub = tok.subdomain || process.env.SHAREFILE_SUBDOMAIN || '';

    console.log('[auth.callback] subdomain from token', sub || '(missing)');

    if (!sub) return new NextResponse('Missing subdomain in token/callback', { status: 400 });

    const sessionId = randomString(24);
    sessionStore.set(sessionId, {
      access_token: tok.access_token,            // do not log
      refresh_token: tok.refresh_token,          // do not log
      token_type: tok.token_type || 'Bearer',
      expires_in: tok.expires_in,
      subdomain: sub,
      obtained_at: Date.now(),
      controlPlane: CONTROL_PLANE,
    });

    const back = new URL(returnToCookie);
    back.searchParams.set('session', sessionId);

    if (AUTH_TRACE || debug) {
      const body = `<!doctype html>
<html><head><meta charset="utf-8"><title>ShareFile Callback Trace</title></head>
<body style="font-family: system-ui, -apple-system, Segoe UI, Arial; padding:16px">
  <h1>Callback Trace</h1>
  <p><strong>Session created:</strong> ${htmlEscape(sessionId)}</p>
  <p><strong>Subdomain:</strong> ${htmlEscape(sub)}</p>
  <p><strong>Redirecting back to:</strong> ${htmlEscape(back.toString())}</p>
  <p><a href="${htmlEscape(back.toString())}">Continue</a></p>
</body></html>`;
      const res = new NextResponse(body, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' }});
      res.cookies.delete('sf_oauth_state');
      res.cookies.delete('sf_oauth_verifier');
      res.cookies.delete('sf_return_to');
      return res;
    }

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

export async function OPTIONS() {
  const res = new NextResponse(null, { status: 204 });
  res.headers.set('Access-Control-Allow-Origin', process.env.ALLOW_ORIGIN || 'http://localhost:3000');
  res.headers.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.headers.set('Access-Control-Allow-Headers', 'Content-Type');
  return res;
}
