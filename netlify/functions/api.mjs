import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const DEF = {
  products: [
    { id: "seller", n: "Customized TG Seller", p: 80, e: "🛍️", d: "Custom-made Telegram seller setup, personalized for your shop.", img: "" },
    { id: "button", n: "Buttons Maker", p: 5, e: "🔘", d: "Custom buttons made to order. ₱5 per button.", img: "" },
    { id: "unl", n: "Unlimited Buttons + TG Premium Emojis", p: 25, e: "✨", d: "Unlimited buttons with Telegram Premium emojis included.", img: "" },
  ],
  gcash: { name: "", no: "", qr: "" },
};
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
const cfg = async () => (await S().get("config", { type: "json" })) || DEF;
const code8 = () => { const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; let s = ""; for (const b of crypto.randomBytes(8)) s += A[b % 32]; return s.slice(0, 4) + "-" + s.slice(4); };
const norm = (c) => String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
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
    const rc = code8();
    us[n] = { h: hash(b.password), name: clip(b.name, 30).trim() || n, rc: hash(norm(rc)) };
    await S().setJSON("users", us);
    return J({ t: sign({ u: n, r: "customer" }), u: n, r: "customer", pic: "", name: us[n].name, rc });
  }

  if (p[0] === "login") {
    const n = clip(b.username, 20).trim().toLowerCase();
    if (env("OWNER_USER") && n === env("OWNER_USER").toLowerCase() && b.password === env("OWNER_PASS"))
      return J({ t: sign({ u: n, r: "owner" }), u: n, r: "owner" });
    const us = await get("users");
    const h = us[n]?.h;
    if (!h || hash(String(b.password || ""), h.split(":")[0]) !== h)
      return J({ error: "Wrong username or password." }, 401);
    return J({ t: sign({ u: n, r: "customer" }), u: n, r: "customer", pic: us[n]?.pic || "", name: us[n]?.name || n });
  }

  if (p[0] === "config" && m === "GET") return J(await cfg());

  if (p[0] === "reset" && m === "POST") {
    const n = clip(b.username, 20).trim().toLowerCase();
    const us = await get("users");
    const x = us[n];
    const pw = String(b.password || "");
    if (!x || !x.rc || pw.length < 6) return J({ error: "Check your username, recovery code and new password (6+ characters)." }, 400);
    if ((x.fails || 0) >= 8 && Date.now() - (x.failAt || 0) < 900000) return J({ error: "Too many tries. Please try again in 15 minutes." }, 429);
    if (hash(norm(b.code), x.rc.split(":")[0]) !== x.rc) {
      x.fails = (x.fails || 0) + 1; x.failAt = Date.now();
      await S().setJSON("users", us);
      return J({ error: "That recovery code doesn’t match." }, 401);
    }
    x.h = hash(pw); x.fails = 0;
    await S().setJSON("users", us);
    return J({ ok: true });
  }

  if (p[0] === "forgot" && m === "POST") {
    const n = clip(b.username, 20).trim().toLowerCase();
    const us = await get("users");
    if (us[n]) {
      const rs = await get("resets");
      if (!rs.includes(n)) { rs.push(n); await S().setJSON("resets", rs); }
    }
    return J({ ok: true });
  }

  if (p[0] === "reviews" && m === "GET") {
    const r = await get("reviews");
    const us = await get("users");
    if (own && u.searchParams.get("all"))
      return J(r.map((x) => ({ ...x, pic: us[x.u]?.pic || "", name: us[x.u]?.name || x.u })));
    return J(r.filter((x) => x.show).map((x) => ({ stars: x.stars, text: x.text, at: x.at, pic: us[x.u]?.pic || "", name: us[x.u]?.name || "Customer" })));
  }

  if (!me) return J({ error: "Please log in first." }, 401);

  if (p[0] === "config" && m === "POST") {
    if (!own) return J({ error: "Owner only." }, 403);
    const img = (v, max) => (typeof v === "string" && v.startsWith("data:image/") && v.length <= max ? v : "");
    const seen = new Set();
    const ps = (Array.isArray(b.products) ? b.products : []).slice(0, 30).map((q, i) => {
      let id = /^[a-z0-9-]{1,24}$/.test(String(q.id)) ? q.id : "p" + i + Date.now().toString(36);
      while (seen.has(id)) id += "x";
      seen.add(id);
      return { id, n: clip(q.n, 80) || "Item", p: Math.min(1e6, Math.max(0, Number(q.p) || 0)), d: clip(q.d, 400), e: clip(q.e, 4) || "🎀", img: img(q.img, 150000) };
    });
    const g = b.gcash || {};
    const c = { products: ps, gcash: { name: clip(g.name, 60), no: clip(g.no, 40), qr: img(g.qr, 400000) } };
    await S().setJSON("config", c);
    return J(c);
  }

  if (p[0] === "profile" && m === "POST") {
    if (own) return J({ error: "The owner has no customer profile." }, 400);
    const us = await get("users");
    const x = us[me.u];
    if (!x) return J({ error: "Account not found." }, 404);
    if (b.name !== undefined) x.name = clip(b.name, 30).trim() || me.u;
    if (b.pic !== undefined) {
      const pic = String(b.pic || "");
      if (!pic.startsWith("data:image/jpeg;base64,") || pic.length > 30000) return J({ error: "Invalid photo." }, 400);
      x.pic = pic;
    }
    await S().setJSON("users", us);
    return J({ pic: x.pic || "", name: x.name || me.u });
  }

  if (p[0] === "password" && m === "POST") {
    const us = await get("users");
    const x = us[me.u];
    if (own || !x) return J({ error: "Not available." }, 400);
    if (hash(String(b.old || ""), x.h.split(":")[0]) !== x.h) return J({ error: "Your current password is wrong." }, 401);
    if (String(b.password || "").length < 6) return J({ error: "New password must be 6+ characters." }, 400);
    x.h = hash(String(b.password));
    await S().setJSON("users", us);
    return J({ ok: true });
  }

  if (p[0] === "recovery" && m === "POST") {
    const us = await get("users");
    const x = us[me.u];
    if (own || !x) return J({ error: "Not available." }, 400);
    const rc = code8();
    x.rc = hash(norm(rc)); x.fails = 0;
    await S().setJSON("users", us);
    return J({ rc });
  }

  if (p[0] === "resets" && m === "GET") {
    if (!own) return J({ error: "Owner only." }, 403);
    return J(await get("resets"));
  }

  if (p[0] === "ownerreset" && m === "POST") {
    if (!own) return J({ error: "Owner only." }, 403);
    const n = clip(b.username, 20).trim().toLowerCase();
    const us = await get("users");
    if (!us[n]) return J({ error: "No customer with that username." }, 404);
    const temp = crypto.randomBytes(5).toString("hex");
    us[n].h = hash(temp); us[n].fails = 0;
    await S().setJSON("users", us);
    await S().setJSON("resets", (await get("resets")).filter((v) => v !== n));
    return J({ u: n, temp });
  }

  if (p[0] === "orders") {
    const o = await get("orders");
    if (m === "GET") {
      if (!own) return J(o.filter((x) => x.u === me.u));
      const us = await get("users");
      return J(o.map((x) => ({ ...x, pic: us[x.u]?.pic || "", name: us[x.u]?.name || x.u })));
    }

    if (!p[1]) {
      const cf = await cfg();
      const pm = Object.fromEntries(cf.products.map((q) => [q.id, q]));
      const it = (Array.isArray(b.items) ? b.items : [])
        .filter((i) => pm[i.id] && i.q > 0)
        .slice(0, 10)
        .map((i) => ({ id: i.id, q: Math.min(Math.floor(i.q), 999), n: pm[i.id].n, p: pm[i.id].p }));
      if (own || !it.length) return J({ error: "Invalid order." }, 400);
      const x = {
        id: Date.now().toString(36), u: me.u, items: it,
        total: it.reduce((s, i) => s + i.p * i.q, 0),
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

