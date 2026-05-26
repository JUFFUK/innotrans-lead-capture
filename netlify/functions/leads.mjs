import { getStore } from "@netlify/blobs";

function getBlobStore() {
  if (Netlify.env.get("CONTEXT") === "production") {
    return getStore("innotrans-leads");
  }
  return getStore({ name: "innotrans-leads", consistency: "strong" });
}

async function getSession(req) {
  const authHeader = req.headers.get("authorization") || "";
  const token = authHeader.replace("Bearer ", "").trim();
  if (!token) return null;
  const userStore = Netlify.env.get("CONTEXT") === "production"
    ? getStore("innotrans-users")
    : getStore({ name: "innotrans-users", consistency: "strong" });
  const session = await userStore.get("session:" + token, { type: "json" });
  if (!session || Date.now() > session.expiry) return null;
  return session;
}

export default async (req) => {
  const session = await getSession(req);
  if (!session) {
    return Response.json({ error: "Unauthorised" }, { status: 401 });
  }

  const url = new URL(req.url);
  const method = req.method;
  const store = getBlobStore();

  if (method === "GET") {
    const { blobs } = await store.list();
    const leads = await Promise.all(
      blobs.map(b => store.get(b.key, { type: "json" }))
    );
    const valid = leads.filter(Boolean);
    const filtered = session.role === "manager"
      ? valid
      : valid.filter(l => l.capturedBy === session.userId);
    filtered.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    return Response.json(filtered);
  }

  if (method === "POST") {
    const body = await req.json();
    const id = "lead_" + Date.now() + "_" + Math.random().toString(36).slice(2, 8);
    const lead = {
      id,
      ...body,
      capturedBy: session.userId,
      capturedByName: session.name,
      synced: false,
      createdAt: new Date().toISOString()
    };
    await store.setJSON(id, lead);
    return Response.json(lead, { status: 201 });
  }

  if (method === "PATCH") {
    const id = url.searchParams.get("id");
    if (!id) return Response.json({ error: "Lead ID required" }, { status: 400 });
    const existing = await store.get(id, { type: "json" });
    if (!existing) return Response.json({ error: "Lead not found" }, { status: 404 });
    if (session.role !== "manager" && existing.capturedBy !== session.userId) {
      return Response.json({ error: "Forbidden" }, { status: 403 });
    }
    const updates = await req.json();
    const updated = { ...existing, ...updates, id, updatedAt: new Date().toISOString() };
    await store.setJSON(id, updated);
    return Response.json(updated);
  }

  if (method === "DELETE") {
    const id = url.searchParams.get("id");
    if (!id) return Response.json({ error: "Lead ID required" }, { status: 400 });
    const existing = await store.get(id, { type: "json" });
    if (!existing) return Response.json({ error: "Lead not found" }, { status: 404 });
    if (session.role !== "manager" && existing.capturedBy !== session.userId) {
      return Response.json({ error: "Forbidden" }, { status: 403 });
    }
    await store.delete(id);
    return Response.json({ success: true });
  }

  return Response.json({ error: "Method not allowed" }, { status: 405 });
};

export const config = {
  path: "/api/leads"
};
