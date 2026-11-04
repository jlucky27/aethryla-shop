import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const PR = { seller: 80, button: 5, unl: 25 };
const env = (k) => process.env[k] || "";
const SEC = () => env("SECRET") || env("OWNER_PASS") || "change-me";
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const mac = (b) => crypto.createHmac("sha256", SEC()).update(b).digest("base64url");
const sign = (p) => { const b = b64(p); return b + "." + mac(b); };
const verify = (t) => {
  if (!t) return null;
  const [b, s] = t.split(".");
  if (!s || mac(b) !== s) return null;
  try { return JSON.parse(Buffer.from(b, "base64url")); } catch { return null; }
};
const hash = (p, salt = crypto.randomBytes(8).toString("hex")) =>
  salt + ":" + crypto.scryptSync(p, salt, 32).toString("hex");
const J = (d, s = 200) =>
  new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json" } });
const S = () => getStore("shop");
const get = async (k) => (await S().get(k, { type: "json" })) || (k === "users" ? {} : []);
const clip = (v, n) => String(v || "").slice(0, n);

export default async (req) => {
  const u = new URL(req.url);
  const p = u.pathname.replace(/^\/api\//, "").split("/");
  const m = req.method;
  const b = m === "POST" ? await req.json().catch(() => ({})) : {};
  const me = verify((req.headers.get("authorization") || "").slice(7));
  const own = me?.r === "owner";

  if (p[0] === "register") {
    const us = await get("users");
    const n = clip(b.username, 20).trim().toLowerCase();
    if (!/^[a-z0-9_]{3,20}$/.test(n) || clip(b.password, 100).length < 6)
      return J({ error: "Username: 3-20 letters, numbers or _. Password: 6+ characters." }, 400);
    if (us[n] || n === env("OWNER_USER").toLowerCase()) return J({ error: "That username is taken." }, 409);
    us[n] = { h: hash(b.password) };
    await S().setJSON("users", us);
    return J({ t: sign({ u: n, r: "customer" }), u: n, r: "customer" });
  }

  if (p[0] === "login") {
    const n = clip(b.username, 20).trim().toLowerCase();
    if (env("OWNER_USER") && n === env("OWNER_USER").toLowerCase() && b.password === env("OWNER_PASS"))
      return J({ t: sign({ u: n, r: "owner" }), u: n, r: "owner" });
    const us = await get("users");
    const h = us[n]?.h;
    if (!h || hash(String(b.password || ""), h.split(":")[0]) !== h)
      return J({ error: "Wrong username or password." }, 401);
    return J({ t: sign({ u: n, r: "customer" }), u: n, r: "customer" });
  }

  if (p[0] === "reviews" && m === "GET") {
    const r = await get("reviews");
    return J(own && u.searchParams.get("all") ? r : r.filter((x) => x.show));
  }

  if (!me) return J({ error: "Please log in first." }, 401);

  if (p[0] === "orders") {
    const o = await get("orders");
    if (m === "GET") return J(own ? o : o.filter((x) => x.u === me.u));

    if (!p[1]) {
      const it = (Array.isArray(b.items) ? b.items : [])
        .filter((i) => PR[i.id] && i.q > 0)
        .slice(0, 10)
        .map((i) => ({ id: i.id, q: Math.min(Math.floor(i.q), 999) }));
      if (own || !it.length) return J({ error: "Invalid order." }, 400);
      const x = {
        id: Date.now().toString(36), u: me.u, items: it,
        total: it.reduce((s, i) => s + PR[i.id] * i.q, 0),
        contact: clip(b.contact, 100), ref: clip(b.ref, 60), note: clip(b.note, 500),
        status: "pending", at: Date.now(),
      };
      o.push(x);
      await S().setJSON("orders", o);
      return J(x);
    }

    const x = o.find((i) => i.id === p[1]);
    if (!x) return J({ error: "Order not found." }, 404);

    if (p[2] === "status") {
      if (!own) return J({ error: "Owner only." }, 403);
      if (!["processing", "declined", "delivered"].includes(b.status)) return J({ error: "Invalid status." }, 400);
      x.status = b.status;
    } else if (p[2] === "review") {
      if (x.u !== me.u || x.status !== "delivered" || x.reviewed) return J({ error: "You can't review this order." }, 403);
      const rv = await get("reviews");
      rv.push({ id: x.id, u: me.u, stars: Math.min(5, Math.max(1, Number(b.stars) || 5)), text: clip(b.text, 400), show: false, at: Date.now() });
      await S().setJSON("reviews", rv);
      x.reviewed = true;
    } else return J({ error: "Not found." }, 404);

    await S().setJSON("orders", o);
    return J(x);
  }

  if (p[0] === "reviews" && p[1] && p[2] === "show") {
    if (!own) return J({ error: "Owner only." }, 403);
    const rv = await get("reviews");
    const r = rv.find((i) => i.id === p[1]);
    if (!r) return J({ error: "Review not found." }, 404);
    r.show = !!b.show;
    await S().setJSON("reviews", rv);
    return J(r);
  }

  return J({ error: "Not found." }, 404);
};

export const config = { path: "/api/*" };

