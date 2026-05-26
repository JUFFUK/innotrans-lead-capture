import { getStore } from "@netlify/blobs";
import bcrypt from "bcryptjs";

function getBlobStore() {
  if (Netlify.env.get("CONTEXT") === "production") {
    return getStore("innotrans-users");
  }
  return getStore({ name: "innotrans-users", consistency: "strong" });
}

function generateToken() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let token = "";
  for (let i = 0; i < 64; i++) {
    token += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return token;
}

export default async (req) => {
  const url = new URL(req.url);
  const action = url.searchParams.get("action");

  if (req.method === "POST" && action === "login") {
    const { email, password } = await req.json();
    if (!email || !password) {
      return Response.json({ error: "Email and password required" }, { status: 400 });
    }
    const store = getBlobStore();
    const user = await store.get("user:" + email.toLowerCase(), { type: "json" });
    if (!user) {
      return Response.json({ error: "Invalid email or password" }, { status: 401 });
    }
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      return Response.json({ error: "Invalid email or password" }, { status: 401 });
    }
    const token = generateToken();
    const sessionExpiry = Date.now() + 8 * 60 * 60 * 1000;
    await store.setJSON("session:" + token, {
      userId: email.toLowerCase(),
      name: user.name,
      role: user.role,
      expiry: sessionExpiry
    });
    return Response.json({
      token,
      name: user.name,
      email: email.toLowerCase(),
      role: user.role
    });
  }

  if (req.method === "POST" && action === "register") {
    const { email, password, name, role, adminSecret } = await req.json();
    if (!email || !password || !name) {
      return Response.json({ error: "Name, email and password required" }, { status: 400 });
    }
    const expectedSecret = Netlify.env.get("ADMIN_SECRET");
    if (!expectedSecret || adminSecret !== expectedSecret) {
      return Response.json({ error: "Invalid admin secret" }, { status: 403 });
    }
    const store = getBlobStore();
    const existing = await store.get("user:" + email.toLowerCase());
    if (existing) {
      return Response.json({ error: "User already exists" }, { status: 409 });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    await store.setJSON("user:" + email.toLowerCase(), {
      name,
      email: email.toLowerCase(),
      role: role === "manager" ? "manager" : "rep",
      passwordHash,
      createdAt: new Date().toISOString()
    });
    return Response.json({ success: true });
  }

  if (req.method === "POST" && action === "logout") {
    const authHeader = req.headers.get("authorization") || "";
    const token = authHeader.replace("Bearer ", "").trim();
    if (token) {
      const store = getBlobStore();
      await store.delete("session:" + token);
    }
    return Response.json({ success: true });
  }

  if (req.method === "GET" && action === "verify") {
    const authHeader = req.headers.get("authorization") || "";
    const token = authHeader.replace("Bearer ", "").trim();
    if (!token) return Response.json({ valid: false }, { status: 401 });
    const store = getBlobStore();
    const session = await store.get("session:" + token, { type: "json" });
    if (!session || Date.now() > session.expiry) {
      return Response.json({ valid: false }, { status: 401 });
    }
    return Response.json({ valid: true, name: session.name, email: session.userId, role: session.role });
  }

  return Response.json({ error: "Not found" }, { status: 404 });
};

export const config = {
  path: "/api/auth"
};
