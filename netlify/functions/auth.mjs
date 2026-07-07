// Pure Web Crypto — no external dependencies needed

const ALLOWED_ORIGINS = new Set([
  'https://leads.trelleborg.one',
  'https://trelleborg.one'
]);

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.has(origin) ? origin : ALLOWED_ORIGINS.values().next().value;
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Vary': 'Origin'
  };
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const hashBuffer = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, 256);
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, "0")).join("");
  const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
  return saltHex + ":" + hashHex;
}

async function verifyPassword(password, stored) {
  const encoder = new TextEncoder();
  const [saltHex, hashHex] = stored.split(":");
  if (!saltHex || !hashHex) return false;
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
  const keyMaterial = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const hashBuffer = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, 256);
  const newHashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
  return newHashHex === hashHex;
}

function generateToken() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let token = "";
  const arr = crypto.getRandomValues(new Uint8Array(64));
  arr.forEach(b => { token += chars[b % chars.length]; });
  return token;
}

function json(data, status = 200, origin = '') {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(origin) }
  });
}

async function isLoginLocked(env, key) {
  const attempts = await env.USERS.get("loginattempts:" + key, { type: "json" });
  if (!attempts) return false;
  return attempts.count >= 5 && Date.now() < attempts.lockedUntil;
}

async function recordFailedLogin(env, key) {
  const existing = await env.USERS.get("loginattempts:" + key, { type: "json" });
  const count = (existing?.count || 0) + 1;
  const lockedUntil = count >= 5 ? Date.now() + 15 * 60 * 1000 : 0;
  await env.USERS.put("loginattempts:" + key, JSON.stringify({ count, lockedUntil }), { expirationTtl: 900 });
}

async function clearFailedLogins(env, key) {
  await env.USERS.delete("loginattempts:" + key);
}

export async function onRequest({ request, env }) {
  const origin = request.headers.get('Origin') || '';

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders(origin) });
  }

  const url = new URL(request.url);
  const action = url.searchParams.get("action");

  // ── LOGIN ──
  if (request.method === "POST" && action === "login") {
    const { email, password } = await request.json();
    if (!email || !password) return json({ error: "Email and password required" }, 400, origin);

    const key = email.toLowerCase();
    if (await isLoginLocked(env, key)) {
      return json({ error: "Too many failed attempts, try again in 15 minutes" }, 429, origin);
    }

    const user = await env.USERS.get("user:" + key, { type: "json" });
    if (!user) {
      await recordFailedLogin(env, key);
      return json({ error: "Invalid email or password" }, 401, origin);
    }
    const valid = user.passwordHash
      ? await verifyPassword(password, user.passwordHash)
      : false;
    if (!valid) {
      await recordFailedLogin(env, key);
      return json({ error: "Invalid email or password" }, 401, origin);
    }

    await clearFailedLogins(env, key);
    const token = generateToken();
    const expiry = Date.now() + 8 * 60 * 60 * 1000;
    await env.USERS.put("user:" + key, JSON.stringify({
      ...user,
      lastLoginAt: new Date().toISOString()
    }));
    await env.USERS.put("session:" + token, JSON.stringify({
      userId: key, name: user.name, role: user.role, expiry
    }), { expirationTtl: 28800 });
    return json({ token, name: user.name, email: key, role: user.role }, 200, origin);
  }

  // ── REGISTER ──
  if (request.method === "POST" && action === "register") {
    const { email, password, name, role, adminSecret } = await request.json();
    if (!email || !password || !name) return json({ error: "Name, email and password required" }, 400, origin);
    if (adminSecret !== env.ADMIN_SECRET) return json({ error: "Invalid admin secret" }, 403, origin);
    if (password.length < 10) return json({ error: "Password must be at least 10 characters" }, 400, origin);
    const existing = await env.USERS.get("user:" + email.toLowerCase());
    if (existing) return json({ error: "User already exists" }, 409, origin);
    const passwordHash = await hashPassword(password);
    await env.USERS.put("user:" + email.toLowerCase(), JSON.stringify({
      name, email: email.toLowerCase(),
      role: role === "manager" ? "manager" : "team",
      passwordHash, createdAt: new Date().toISOString(),
      lastLoginAt: null
    }));
    return json({ success: true }, 200, origin);
  }

  // ── LOGOUT ──
  if (request.method === "POST" && action === "logout") {
    const token = (request.headers.get("authorization") || "").replace("Bearer ", "").trim();
    if (token) await env.USERS.delete("session:" + token);
    return json({ success: true }, 200, origin);
  }

  // ── VERIFY ──
  if (request.method === "GET" && action === "verify") {
    const token = (request.headers.get("authorization") || "").replace("Bearer ", "").trim();
    if (!token) return json({ valid: false }, 401, origin);
    const session = await env.USERS.get("session:" + token, { type: "json" });
    if (!session || Date.now() > session.expiry) return json({ valid: false }, 401, origin);
    return json({ valid: true, name: session.name, email: session.userId, role: session.role }, 200, origin);
  }

  // ── LIST USERS (manager only) ──
  if (request.method === "GET" && action === "list-users") {
    const token = (request.headers.get("authorization") || "").replace("Bearer ", "").trim();
    if (!token) return json({ error: "Unauthorised" }, 401, origin);
    const session = await env.USERS.get("session:" + token, { type: "json" });
    if (!session || Date.now() > session.expiry) return json({ error: "Unauthorised" }, 401, origin);
    if (session.role !== "manager") return json({ error: "Forbidden" }, 403, origin);
    const list = await env.USERS.list({ prefix: "user:" });
    const users = await Promise.all(
      list.keys.map(k => env.USERS.get(k.name, { type: "json" }))
    );
    const safe = users.filter(Boolean).map(u => ({
      name: u.name,
      email: u.email,
      role: u.role,
      createdAt: u.createdAt,
      lastLoginAt: u.lastLoginAt || null
    }));
    safe.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
    return json(safe, 200, origin);
  }

  // ── DELETE USER (manager only) ──
  if (request.method === "POST" && action === "delete-user") {
    const token = (request.headers.get("authorization") || "").replace("Bearer ", "").trim();
    if (!token) return json({ error: "Unauthorised" }, 401, origin);
    const session = await env.USERS.get("session:" + token, { type: "json" });
    if (!session || Date.now() > session.expiry) return json({ error: "Unauthorised" }, 401, origin);
    if (session.role !== "manager") return json({ error: "Forbidden" }, 403, origin);
    const { email } = await request.json();
    if (!email) return json({ error: "Email required" }, 400, origin);
    if (email.toLowerCase() === session.userId) return json({ error: "You cannot delete your own account" }, 400, origin);
    await env.USERS.delete("user:" + email.toLowerCase());
    return json({ success: true }, 200, origin);
  }

  // ── UPDATE USER ROLE (manager only) ──
  if (request.method === "POST" && action === "update-role") {
    const token = (request.headers.get("authorization") || "").replace("Bearer ", "").trim();
    if (!token) return json({ error: "Unauthorised" }, 401, origin);
    const session = await env.USERS.get("session:" + token, { type: "json" });
    if (!session || Date.now() > session.expiry) return json({ error: "Unauthorised" }, 401, origin);
    if (session.role !== "manager") return json({ error: "Forbidden" }, 403, origin);
    const { email, role } = await request.json();
    if (!email || !role) return json({ error: "Email and role required" }, 400, origin);
    if (email.toLowerCase() === session.userId) return json({ error: "You cannot change your own role" }, 400, origin);
    const user = await env.USERS.get("user:" + email.toLowerCase(), { type: "json" });
    if (!user) return json({ error: "User not found" }, 404, origin);
    await env.USERS.put("user:" + email.toLowerCase(), JSON.stringify({
      ...user,
      role: role === "manager" ? "manager" : "team"
    }));
    return json({ success: true }, 200, origin);
  }

  return json({ error: "Not found" }, 404, origin);
}
