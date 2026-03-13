// Tenant-pinned broker route.ts
import { NextRequest, NextResponse } from 'next/server';
import { webcrypto as nodeWebcrypto } from 'crypto';
const cryptoImpl = (globalThis.crypto ?? nodeWebcrypto);
const CLIENT_ID=process.env.SHAREFILE_CLIENT_ID!;
const CLIENT_SECRET=process.env.SHAREFILE_CLIENT_SECRET!;
const SUB=process.env.SHAREFILE_SUBDOMAIN||'';
function b64url(b){return Buffer.from(b).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
async function sha256(s){return b64url(new Uint8Array(await cryptoImpl.subtle.digest('SHA-256', new TextEncoder().encode(s))));}
function rnd(n){let u=new Uint8Array(n);cryptoImpl.getRandomValues(u);return b64url(u);} 
const sessionStore=new Map();
export async function GET(req:NextRequest){
 const url=new URL(req.url); const action=url.searchParams.get('action');
 if(action==='start'){
   const returnTo=url.searchParams.get('return')||'http://localhost:3000/oauth/callback';
   const state=rnd(16); const verifier=rnd(64); const challenge=await sha256(verifier);
   const redirectUri=`${req.nextUrl.origin}/api/sharefile?action=callback`;
   // tenant-pinned domain
   const base = SUB?`https://${SUB}.sharefile.com`:'https://secure.sharefile.com';
   const auth=new URL(base+'/oauth/authorize');
   auth.searchParams.set('response_type','code');
   auth.searchParams.set('client_id',CLIENT_ID);
   auth.searchParams.set('redirect_uri',redirectUri);
   auth.searchParams.set('state',state);
   auth.searchParams.set('code_challenge',challenge);
   auth.searchParams.set('code_challenge_method','S256');
   if(SUB){auth.searchParams.set('acr_values',`tenant:${SUB}`); auth.searchParams.set('subdomain',SUB);}    
   const res=NextResponse.redirect(auth.toString());
   res.cookies.set('sf_oauth_state',state,{httpOnly:true,sameSite:'lax',secure:true,path:'/'});
   res.cookies.set('sf_oauth_verifier',verifier,{httpOnly:true,sameSite:'lax',secure:true,path:'/'});
   res.cookies.set('sf_return_to',returnTo,{httpOnly:true,sameSite:'lax',secure:true,path:'/'});
   return res;
 }
 if(action==='callback'){
   const u=new URL(req.url); const code=u.searchParams.get('code')||''; const state=u.searchParams.get('state')||'';
   const cState=req.cookies.get('sf_oauth_state')?.value;
   const verifier=req.cookies.get('sf_oauth_verifier')?.value;
   const returnTo=req.cookies.get('sf_return_to')?.value;
   if(!state||state!==cState||!verifier||!returnTo) return new NextResponse('Invalid state',{status:400});
   const tokRes=await fetch('https://secure.sharefile.com/oauth/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id:CLIENT_ID,client_secret:CLIENT_SECRET,code,redirect_uri:`${req.nextUrl.origin}/api/sharefile?action=callback`,code_verifier:verifier})});
   if(!tokRes.ok) return new NextResponse('Token exchange failed',{status:500});
   const tok=await tokRes.json(); const sub=tok.subdomain||SUB||''; if(!sub) return new NextResponse('Missing subdomain',{status:400});
   const sid=rnd(24); sessionStore.set(sid,{access_token:tok.access_token,refresh_token:tok.refresh_token,expires_in:tok.expires_in,subdomain:sub});
   const back=new URL(returnTo); back.searchParams.set('session',sid);
   const res=NextResponse.redirect(back.toString());
   res.cookies.delete('sf_oauth_state');res.cookies.delete('sf_oauth_verifier');res.cookies.delete('sf_return_to'); return res;
 }
 if(action==='session'){
   const id=url.searchParams.get('id')||''; const data=sessionStore.get(id);
   if(!data) return new NextResponse('Not found',{status:404}); return NextResponse.json(data);
 }
 return new NextResponse('Not Found',{status:404});
}
export async function OPTIONS(){return new NextResponse(null,{status:204});}
