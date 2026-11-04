// Cloudflare Pages Function: /api/auth
// GET  -> { configured: true|false }  (has the owner password been created?)
// POST -> { password }
//         • first time: creates the owner password (stored as a salted SHA-256 hash)
//         • afterwards: checks the password, 403 if wrong
// Needs only the KV binding "STORE" (no environment variables).

const JSON_HEADERS = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" };
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: JSON_HEADERS });

function toHex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join(""); }

async function hashPassword(salt, password) {
  const data = new TextEncoder().encode(salt + ":" + password);
  return toHex(await crypto.subtle.digest("SHA-256", data));
}

export async function onRequestGet({ env }) {
  if (!env.STORE) return json({ error: "storage not configured" }, 500);
  const auth = await env.STORE.get("auth", "json");
  return json({ configured: !!auth });
}

export async function onRequestPost({ request, env }) {
  if (!env.STORE) return json({ error: "storage not configured" }, 500);
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: "bad request" }, 400); }
  const password = typeof body.password === "string" ? body.password : "";
  if (password.length < 6 || password.length > 200) return json({ error: "password must be 6-200 characters" }, 400);

  const auth = await env.STORE.get("auth", "json");
  if (!auth) {
    const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
    const hash = await hashPassword(salt, password);
    await env.STORE.put("auth", JSON.stringify({ salt, hash, created: new Date().toISOString() }));
    return json({ ok: true, created: true });
  }
  if (await hashPassword(auth.salt, password) !== auth.hash) return json({ error: "forbidden" }, 403);
  return json({ ok: true });
}
