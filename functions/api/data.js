// Cloudflare Pages Function: /api/data
// GET  -> the stop list and the added perfumes (anyone can read)
// POST -> saves them; needs the owner password in the X-Owner-Token header
//         (the password is created on the admin page, see auth.js)

const JSON_HEADERS = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" };
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: JSON_HEADERS });

function toHex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join(""); }

async function hashPassword(salt, password) {
  const data = new TextEncoder().encode(salt + ":" + password);
  return toHex(await crypto.subtle.digest("SHA-256", data));
}

// is the given password the owner's?
async function isOwner(env, password) {
  const auth = await env.STORE.get("auth", "json");
  if (!auth || typeof password !== "string" || !password) return false;
  const hash = await hashPassword(auth.salt, password);
  let diff = hash.length ^ auth.hash.length;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ auth.hash.charCodeAt(i);
  return diff === 0;
}

function cleanExtra(item) {
  const name = String(item && item.name || "").trim().slice(0, 80);
  const g = ["U", "M", "W"].includes(item && item.g) ? item.g : "U";
  const flags = [0, 1, 2].map(i => !!(item && item.flags && item.flags[i]));
  return { name, g, flags };
}

export async function onRequestGet({ env }) {
  const data = env.STORE ? await env.STORE.get("data", "json") : null;
  return json(data || { out: [], extra: [] });
}

export async function onRequestPost({ request, env }) {
  if (!env.STORE) return json({ error: "storage not configured" }, 500);
  if (!(await isOwner(env, request.headers.get("X-Owner-Token") || ""))) {
    return json({ error: "forbidden" }, 403);
  }
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: "bad request" }, 400); }
  const data = {
    out: (Array.isArray(body.out) ? body.out : []).slice(0, 5000).map(String),
    extra: (Array.isArray(body.extra) ? body.extra : []).filter(x => x && x.name).slice(0, 500).map(cleanExtra),
    updated: new Date().toISOString(),
  };
  await env.STORE.put("data", JSON.stringify(data));
  return json({ ok: true, updated: data.updated });
}
