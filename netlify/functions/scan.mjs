import { getStore } from "@netlify/blobs";

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

  const apiKey = Netlify.env.get("ANTHROPIC_API_KEY");
  if (!apiKey) {
    return Response.json({ error: "API key not configured" }, { status: 500 });
  }

  const { imageBase64, imageType } = await req.json();
  if (!imageBase64 || !imageType) {
    return Response.json({ error: "Image data required" }, { status: 400 });
  }

  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01"
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 1000,
      messages: [{
        role: "user",
        content: [
          {
            type: "image",
            source: { type: "base64", media_type: imageType, data: imageBase64 }
          },
          {
            type: "text",
            text: "This is a business card. Extract contact details and return ONLY a JSON object with keys: firstName, lastName, email, phone, company, jobTitle. Use empty string for missing fields. No preamble, no markdown, raw JSON only."
          }
        ]
      }]
    })
  });

  const data = await response.json();

  if (!response.ok) {
    return Response.json({ error: data.error?.message || "AI extraction failed" }, { status: 500 });
  }

  const raw = data.content.filter(b => b.type === "text").map(b => b.text).join("");
  try {
    const parsed = JSON.parse(raw.replace(/```json|```/g, "").trim());
    return Response.json(parsed);
  } catch (e) {
    return Response.json({ error: "Could not parse card details" }, { status: 500 });
  }
};

export const config = {
  path: "/api/scan"
};
