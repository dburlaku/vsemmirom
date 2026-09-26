/* «Всем миром» — сервер состояния заказа.
   Один файл, одна зависимость (pg). Запускается под systemd, nginx проксирует /api/.

   Модель доступа:
     • владелец — знает id заказа, он же секрет ссылки ?order=<id>;
     • участник — знает свой токен, ссылка ?i=<token>;
     • у участника нет доступа к id заказа: ему отдаётся публичный pid.
*/
"use strict";
const http = require("node:http");
const crypto = require("node:crypto");
const { Pool } = require("pg");

const PORT = +(process.env.PORT || 8081);
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const INV_LIMIT = 20;                   // участников на книгу (§4)
const BURST_N = 8, BURST_MIN = 10;      // входов по общей ссылке за 10 минут
const MAX_BODY = 1 << 20;               // 1 МБ на запрос, кроме макета
const MAX_LAYOUT = 8 << 20;             // макет книги — до 8 МБ

const rnd = (n = 16) => crypto.randomBytes(n).toString("base64url");
const now = () => new Date();

/* ------------------------------------------------ вспомогательное */
function send(res, code, obj) {
  const body = Buffer.from(JSON.stringify(obj ?? {}), "utf8");
  res.writeHead(code, {
    "content-type": "application/json; charset=utf-8",
    "content-length": body.length,
    "cache-control": "no-store"
  });
  res.end(body);
}
const fail = (res, code, error, info) => send(res, code, { error, ...(info || {}) });

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", c => {
      size += c.length;
      if (size > limit) { reject(Object.assign(new Error("too_large"), { code: "too_large" })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch (_) { reject(Object.assign(new Error("bad_json"), { code: "bad_json" })); }
    });
    req.on("error", reject);
  });
}

const str = (v, max = 200) => (v == null ? "" : String(v)).slice(0, max).trim();
const int = (v, def = 0) => (Number.isFinite(+v) ? Math.trunc(+v) : def);

/* простое ограничение частоты: защищает токены от перебора */
const buckets = new Map();
function rateOk(key, limit, windowMs) {
  const t = Date.now();
  const b = buckets.get(key) || [];
  const fresh = b.filter(x => t - x < windowMs);
  fresh.push(t);
  buckets.set(key, fresh);
  if (buckets.size > 5000) for (const [k, v] of buckets) if (!v.length || t - v[v.length - 1] > windowMs) buckets.delete(k);
  return fresh.length <= limit;
}
const ipOf = req => (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress || "?";

/* ------------------------------------------------ представления */
function ownerView(o, invites, log) {
  return {
    id: o.id, pid: o.pid, createdAt: o.created_at, title: o.title, occasion: o.occasion,
    date: o.event_date ? o.event_date.toISOString().slice(0, 10) : "",
    tier: o.tier, tierPrice: o.tier_price, status: o.status, deliv: o.deliv, people: o.people,
    extraDays: o.extra_days, edition: o.edition, stage: o.stage, access: o.access,
    inviteToken: o.invite_token, revoked: o.revoked, frozen: o.frozen,
    closedAt: o.closed_at, volDecision: o.vol_decision, series: o.series,
    owner: { name: o.owner_name || "", contact: o.owner_contact || "" },
    invites: (invites || []).map(p => ({
      id: p.id, token: p.token, name: p.name, contact: p.contact, status: p.status, items: p.items
    })),
    log: (log || []).map(r => ({ t: +new Date(r.at), who: r.who, act: r.act, info: r.info }))
  };
}
/* участнику — только то, что ему нужно видеть: ни id заказа, ни контактов других людей */
function guestView(o, invites, me) {
  const live = (invites || []).filter(p => p.status !== "removed");
  return {
    pid: o.pid, title: o.title, occasion: o.occasion,
    date: o.event_date ? o.event_date.toISOString().slice(0, 10) : "",
    deliv: o.deliv, extraDays: o.extra_days, stage: o.stage,
    access: { collect: !!o.access.collect, public: !!o.access.public },
    owner: { name: o.owner_name || "" },
    joined: live.filter(p => p.status === "joined" || p.status === "contrib").length,
    items: live.reduce((s, p) => s + (p.items || 0), 0),
    invites: live.map(p => ({ name: p.name, status: p.status, items: p.items })),
    me: me ? { id: me.id, name: me.name, contact: me.contact, status: me.status, items: me.items } : null
  };
}

/* ------------------------------------------------ выборки */
async function loadOrder(db, id) {
  const { rows } = await db.query("select * from orders where id=$1", [id]);
  return rows[0] || null;
}
async function loadFull(db, id) {
  const o = await loadOrder(db, id);
  if (!o) return null;
  const inv = (await db.query("select * from invites where order_id=$1 order by created_at", [id])).rows;
  const lg = (await db.query("select * from log where order_id=$1 order by id desc limit 50", [id])).rows.reverse();
  return ownerView(o, inv, lg);
}
async function logAct(db, id, who, act, info) {
  await db.query("insert into log(order_id,who,act,info) values($1,$2,$3,$4)", [id, str(who, 80) || "владелец", str(act, 120), str(info, 300)]);
}
const touch = (db, id) => db.query("update orders set updated_at=now() where id=$1", [id]);

/* срок сбора: печать и доставка съедают часть времени до праздника */
function deadline(o) {
  if (!o.event_date) return null;
  const days = (o.deliv === "msk" ? 7 : o.deliv === "ru" ? 12 : 10) - (o.extra_days || 0);
  const d = new Date(o.event_date); d.setUTCDate(d.getUTCDate() - days);
  return { date: d, left: Math.ceil((d - now()) / 864e5) };
}
/* сбор закрывается сам, когда срок вышел (§5.2) */
async function autoClose(db, o) {
  if (!o.access.collect) return o;
  const dl = deadline(o);
  if (!dl || dl.left >= 0) return o;
  const access = { ...o.access, collect: false, invite: false };
  await db.query("update orders set access=$2, closed_at=coalesce(closed_at,now()), updated_at=now() where id=$1", [o.id, access]);
  await logAct(db, o.id, "система", "сбор закрыт автоматически", "срок вышел");
  return { ...o, access };
}

/* ------------------------------------------------ маршруты */
const routes = [];
const on = (method, re, fn) => routes.push({ method, re, fn });

on("GET", /^\/api\/health$/, async (ctx) => {
  await ctx.db.query("select 1");
  send(ctx.res, 200, { ok: true, time: now().toISOString() });
});

/* создание заказа из квиза */
on("POST", /^\/api\/orders$/, async ({ req, res, db }) => {
  if (!rateOk("mk:" + ipOf(req), 20, 60 * 60e3)) return fail(res, 429, "too_many");
  const b = await readBody(req, MAX_BODY);
  const id = rnd(16), pid = rnd(9), inviteToken = rnd(12);
  const date = /^\d{4}-\d{2}-\d{2}$/.test(str(b.date, 10)) ? b.date : null;
  await db.query(
    `insert into orders(id,pid,title,occasion,event_date,tier,tier_price,status,deliv,people,
       invite_token,owner_name,owner_contact)
     values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
    [id, pid, str(b.title, 120) || "Книга историй", str(b.occasion, 40) || "birthday", date,
     str(b.tier, 40) || "Момент", int(b.tierPrice), str(b.status, 20) === "paid" ? "paid" : "awaiting",
     str(b.deliv, 20) || "later", Math.max(1, Math.min(200, int(b.people, 1))),
     inviteToken, str(b.owner && b.owner.name, 120), str(b.owner && b.owner.contact, 160)]);
  await logAct(db, id, "владелец", "заказ создан", str(b.tier, 40));
  send(res, 201, await loadFull(db, id));
});

/* владелец: чтение и правка */
on("GET", /^\/api\/orders\/([\w-]{10,64})$/, async ({ res, db, m, req }) => {
  if (!rateOk("rd:" + ipOf(req), 600, 60e3)) return fail(res, 429, "too_many");
  let o = await loadOrder(db, m[1]);
  if (!o) return fail(res, 404, "not_found");
  o = await autoClose(db, o);
  send(res, 200, await loadFull(db, o.id));
});

on("PATCH", /^\/api\/orders\/([\w-]{10,64})$/, async ({ req, res, db, m }) => {
  const id = m[1];
  const o = await loadOrder(db, id);
  if (!o) return fail(res, 404, "not_found");
  const b = await readBody(req, MAX_BODY);
  const set = [], val = [id];
  const put = (col, v) => { val.push(v); set.push(`${col}=$${val.length}`); };

  if (b.title !== undefined) put("title", str(b.title, 120) || o.title);
  if (b.tier !== undefined) put("tier", str(b.tier, 40) || o.tier);
  if (b.tierPrice !== undefined) put("tier_price", int(b.tierPrice));
  if (b.status !== undefined) put("status", str(b.status, 20) === "paid" ? "paid" : "awaiting");
  if (b.extraDays !== undefined) put("extra_days", Math.max(0, Math.min(30, int(b.extraDays))));
  if (b.volDecision !== undefined) put("vol_decision", str(b.volDecision, 40));
  if (b.series !== undefined) put("series", b.series);
  if (b.stage !== undefined) put("stage", str(b.stage, 20) === "book-closed" ? "book-closed" : "collect");
  if (b.owner !== undefined) { put("owner_name", str(b.owner.name, 120)); put("owner_contact", str(b.owner.contact, 160)); }
  if (b.access !== undefined) {
    const a = {
      collect: !!b.access.collect,
      invite: !!b.access.invite,
      public: !!b.access.public
    };
    put("access", a);
    if (!a.collect && o.access.collect) put("closed_at", now());
    // возобновление приглашений выдаёт новый токен: старая ссылка перестаёт работать
    if (a.invite && !o.access.invite) put("invite_token", rnd(12));
    if (a.invite) { put("revoked", false); put("frozen", false); }
  }
  if (b.revoked !== undefined) put("revoked", !!b.revoked);
  if (b.edition !== undefined) put("edition", Math.max(1, Math.min(99, int(b.edition, 1))));

  if (set.length) {
    set.push("updated_at=now()");
    await db.query(`update orders set ${set.join(",")} where id=$1`, val);
  }
  if (b.logAct) await logAct(db, id, b.logWho || "владелец", b.logAct, b.logInfo);
  send(res, 200, await loadFull(db, id));
});

/* участники */
on("POST", /^\/api\/orders\/([\w-]{10,64})\/invites$/, async ({ req, res, db, m }) => {
  const id = m[1];
  const o = await loadOrder(db, id);
  if (!o) return fail(res, 404, "not_found");
  const b = await readBody(req, MAX_BODY);
  const list = Array.isArray(b.people) ? b.people : [b];
  const live = +(await db.query("select count(*)::int c from invites where order_id=$1 and status<>'removed'", [id])).rows[0].c;
  if (live + list.length > INV_LIMIT) return fail(res, 409, "limit", { limit: INV_LIMIT, now: live });
  for (const p of list) {
    const name = str(p.name, 120);
    if (!name) continue;
    await db.query("insert into invites(id,order_id,token,name,contact) values($1,$2,$3,$4,$5)",
      [rnd(8), id, rnd(12), name, str(p.contact, 160)]);
  }
  await touch(db, id);
  send(res, 200, await loadFull(db, id));
});

on("POST", /^\/api\/orders\/([\w-]{10,64})\/invites\/send$/, async ({ res, db, m }) => {
  const id = m[1];
  if (!await loadOrder(db, id)) return fail(res, 404, "not_found");
  const r = await db.query("update invites set status='sent' where order_id=$1 and status='draft' returning id", [id]);
  await logAct(db, id, "владелец", "приглашения отправлены", "участников: " + r.rowCount);
  send(res, 200, await loadFull(db, id));
});

on("DELETE", /^\/api\/orders\/([\w-]{10,64})\/invites\/([\w-]{4,32})$/, async ({ res, db, m }) => {
  const [, id, pid] = m;
  const { rows } = await db.query("update invites set status='removed' where order_id=$1 and id=$2 returning name, items", [id, pid]);
  if (!rows[0]) return fail(res, 404, "not_found");
  await logAct(db, id, "владелец", "участник убран", rows[0].name + (rows[0].items ? ", материалов: " + rows[0].items : ""));
  send(res, 200, await loadFull(db, id));
});

/* макет книги */
on("GET", /^\/api\/orders\/([\w-]{10,64})\/layout$/, async ({ res, db, m }) => {
  const { rows } = await db.query("select doc, rev, updated_at from layouts where order_id=$1", [m[1]]);
  if (!rows[0]) return send(res, 200, { doc: null, rev: 0 });
  send(res, 200, { doc: rows[0].doc, rev: rows[0].rev, updatedAt: rows[0].updated_at });
});

on("PUT", /^\/api\/orders\/([\w-]{10,64})\/layout$/, async ({ req, res, db, m }) => {
  const id = m[1];
  if (!await loadOrder(db, id)) return fail(res, 404, "not_found");
  const b = await readBody(req, MAX_LAYOUT);
  if (!b || typeof b.doc !== "object" || b.doc === null) return fail(res, 400, "bad_doc");
  const { rows } = await db.query(
    `insert into layouts(order_id,doc,rev) values($1,$2,1)
       on conflict (order_id) do update set doc=excluded.doc, rev=layouts.rev+1, updated_at=now()
     returning rev`, [id, b.doc]);
  send(res, 200, { rev: rows[0].rev });
});

/* ---------- участник по ссылке-приглашению ---------- */
async function byToken(db, token) {
  const q = await db.query(
    `select o.*, i.id inv_id, i.name inv_name, i.contact inv_contact, i.status inv_status, i.items inv_items
       from orders o
       left join invites i on i.token=$1 and i.order_id=o.id
      where o.invite_token=$1 or i.token=$1
      limit 1`, [token]);
  const r = q.rows[0];
  if (!r) return null;
  const me = r.inv_id ? { id: r.inv_id, name: r.inv_name, contact: r.inv_contact, status: r.inv_status, items: r.inv_items } : null;
  return { order: r, me };
}

on("GET", /^\/api\/i\/([\w-]{6,64})$/, async ({ req, res, db, m }) => {
  const ip = ipOf(req);
  if (!rateOk("tok:" + ip, 60, 60e3)) return fail(res, 429, "too_many");
  const found = await byToken(db, m[1]);
  if (!found) return fail(res, 404, "not_found");
  let o = await autoClose(db, found.order);
  const me = found.me;

  if (o.revoked) return fail(res, 403, "revoked");
  if (me && me.status === "removed") return fail(res, 403, "removed");
  const known = !!me;                                  // именной участник входит и после закрытия ссылки
  if (!o.access.invite && !known) return fail(res, 403, o.frozen ? "frozen" : "invite_off");
  if (!o.access.collect && !known) return fail(res, 403, "collect_closed");

  const inv = (await db.query("select * from invites where order_id=$1", [o.id])).rows;
  if (!me && o.access.collect) {
    const live = inv.filter(p => p.status !== "removed");
    const joined = live.filter(p => p.status === "joined" || p.status === "contrib").length;
    if (joined >= INV_LIMIT) return fail(res, 409, "limit", { limit: INV_LIMIT });
    // всплеск входов по общей ссылке замораживает приём (§4)
    await db.query("insert into hits(order_id) values($1)", [o.id]);
    const hits = +(await db.query("select count(*)::int c from hits where order_id=$1 and at > now() - ($2||' minutes')::interval", [o.id, BURST_MIN])).rows[0].c;
    if (hits > BURST_N) {
      await db.query("update orders set frozen=true, access=jsonb_set(access,'{invite}','false') where id=$1", [o.id]);
      await logAct(db, o.id, "система", "общая ссылка заморожена", "входов за " + BURST_MIN + " минут: " + hits);
      return fail(res, 403, "frozen");
    }
  }
  if (me && (me.status === "draft" || me.status === "sent")) {
    await db.query("update invites set status='joined' where id=$1", [me.id]);
    await logAct(db, o.id, me.name, "участник открыл приглашение", me.name);
    me.status = "joined";
  }
  send(res, 200, guestView(o, inv, me));
});

/* участник называет себя — один раз, при первом сохранении */
on("POST", /^\/api\/i\/([\w-]{6,64})\/join$/, async ({ req, res, db, m }) => {
  const found = await byToken(db, m[1]);
  if (!found) return fail(res, 404, "not_found");
  const o = found.order;
  if (o.revoked || !o.access.collect) return fail(res, 403, "collect_closed");
  const b = await readBody(req, MAX_BODY);
  const name = str(b.name, 120) || "Участник", contact = str(b.contact, 160);
  let me = found.me;
  if (me) {
    await db.query("update invites set name=coalesce(nullif($2,''),name), contact=coalesce(nullif($3,''),contact), status=case when status='removed' then status else 'joined' end where id=$1", [me.id, name, contact]);
    me = { ...me, name, contact, status: "joined" };
  } else {
    const live = +(await db.query("select count(*)::int c from invites where order_id=$1 and status<>'removed'", [o.id])).rows[0].c;
    if (live >= INV_LIMIT) return fail(res, 409, "limit", { limit: INV_LIMIT });
    const id = rnd(8), token = rnd(12);
    await db.query("insert into invites(id,order_id,token,name,contact,status) values($1,$2,$3,$4,$5,'joined')", [id, o.id, token, name, contact]);
    me = { id, token, name, contact, status: "joined", items: 0 };
  }
  await logAct(db, o.id, name, "участник вошёл", name);
  const inv = (await db.query("select * from invites where order_id=$1", [o.id])).rows;
  send(res, 200, { ...guestView(o, inv, me), token: me.token });
});

/* участник прислал материалы — считаем количество (сами файлы придут на Э1.2 в S3) */
on("POST", /^\/api\/i\/([\w-]{6,64})\/items$/, async ({ req, res, db, m }) => {
  const found = await byToken(db, m[1]);
  if (!found || !found.me) return fail(res, 404, "not_found");
  const o = found.order, me = found.me;
  if (!o.access.collect) return fail(res, 403, "collect_closed");
  const b = await readBody(req, MAX_BODY);
  const n = Math.max(0, Math.min(2000, int(b.n, 0)));
  if (!n) return send(res, 200, { items: me.items });
  const { rows } = await db.query("update invites set items=items+$2, status='contrib' where id=$1 returning items", [me.id, n]);
  await logAct(db, o.id, me.name, "участник добавил материалы", me.name + ": " + n);
  send(res, 200, { items: rows[0].items });
});

/* ------------------------------------------------ сервер */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  const path = url.pathname.replace(/\/+$/, "") || "/";
  if (req.method === "OPTIONS") { res.writeHead(204, { allow: "GET,POST,PATCH,PUT,DELETE" }); return res.end(); }
  const r = routes.find(x => x.method === req.method && x.re.test(path));
  if (!r) return fail(res, 404, "no_route");
  const db = await pool.connect();
  try {
    await r.fn({ req, res, db, m: path.match(r.re), url });
  } catch (e) {
    if (e && (e.code === "bad_json" || e.code === "too_large")) return fail(res, 400, e.code);
    console.error("[api]", req.method, path, e && e.message);
    if (!res.headersSent) fail(res, 500, "server_error");
  } finally {
    db.release();
  }
});

async function main() {
  const db = await pool.connect();
  try {
    const fs = require("node:fs"), p = require("node:path");
    await db.query(fs.readFileSync(p.join(__dirname, "schema.sql"), "utf8"));
  } finally { db.release(); }
  server.listen(PORT, "127.0.0.1", () => console.log("[api] порт " + PORT));
}
if (require.main === module) main().catch(e => { console.error(e); process.exit(1); });

module.exports = { server, pool };
