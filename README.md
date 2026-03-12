# Vercel Auth Broker for ShareFile

This project exposes `/api/sharefile` with `action=start|callback|session` to handle ShareFile OAuth on Vercel, then returns a short-lived `session` code to localhost.

1) Set env vars (Vercel → Settings → Environment Variables) from `.env.example`.
2) Register the **exact** Redirect URI in the ShareFile OAuth app:
   `https://<your-vercel-app>.vercel.app/api/sharefile?action=callback`
3) Deploy.

Local site should link users to:
`https://<your-vercel-app>.vercel.app/api/sharefile?action=start&return=http://localhost:3000/oauth/callback`
