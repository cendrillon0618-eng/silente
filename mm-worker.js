/* ============================================================
   Makemarry Server (Cloudflare Worker)  v1
   役割：
   - 定時（cron）に起きて、いま喋りそうなキャラを判定
   - Anthropic APIでそのキャラのメッセージを生成
   - 受信箱(KV)に保存し、Web Pushで通知を飛ばす
   - アプリからの購読登録・設定保存・受信箱の受け渡し
   必要なもの（Settingsで設定）:
   - KVバインディング: MM_KV
   - シークレット: ANTHROPIC_API_KEY / VAPID_JWK / MM_TOKEN
   - Cronトリガー: *​/30 * * * *  など
   ============================================================ */

const VAPID_PUBLIC = "BKWevdLe1Esq0G1z0tEJGg99n2GSQ269gheI_71wtTe7TGpnCf7_x-BLusBh_0n5hRwDJk9p1iB14yoQL9W_gXs";
const VAPID_SUB = "mailto:makemarry@example.com";

/* ---------------- ユーティリティ ---------------- */
const enc = new TextEncoder();
const b64uToBuf = (s) => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
};
const bufToB64u = (buf) => {
  let bin = "";
  new Uint8Array(buf).forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const concatBuf = (...bufs) => {
  const total = bufs.reduce((n, b) => n + b.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const b of bufs) { out.set(new Uint8Array(b), off); off += b.byteLength; }
  return out;
};
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, x-mm-token",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    },
  });

/* ---------------- Web Push (RFC8291 aes128gcm + VAPID) ---------------- */
async function hkdf(salt, ikm, info, len) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info }, key, len * 8));
}

async function encryptPayload(subscription, plaintext) {
  const uaPub = b64uToBuf(subscription.keys.p256dh);
  const authSecret = b64uToBuf(subscription.keys.auth);
  const asKeys = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", asKeys.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, asKeys.privateKey, 256));

  const keyInfo = concatBuf(enc.encode("WebPush: info\0"), uaPub, asPubRaw);
  const ikm = await hkdf(authSecret, ecdh, keyInfo, 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);

  const record = concatBuf(enc.encode(plaintext), new Uint8Array([2]));
  const aesKey = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, record));

  // ヘッダー: salt(16) + rs(4) + idlen(1) + as_public(65)
  const header = new Uint8Array(16 + 4 + 1 + 65);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096);
  header[20] = 65;
  header.set(asPubRaw, 21);
  return concatBuf(header, cipher);
}

async function vapidJwt(audience, env) {
  const jwk = JSON.parse(env.VAPID_JWK);
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const h = bufToB64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const p = bufToB64u(enc.encode(JSON.stringify({
    aud: audience, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: VAPID_SUB,
  })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(h + "." + p));
  return h + "." + p + "." + bufToB64u(sig);
}

async function sendPush(subscription, payloadObj, env) {
  const body = await encryptPayload(subscription, JSON.stringify(payloadObj));
  const aud = new URL(subscription.endpoint).origin;
  const jwt = await vapidJwt(aud, env);
  const res = await fetch(subscription.endpoint, {
    method: "POST",
    headers: {
      "TTL": "86400",
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      "Authorization": `vapid t=${jwt}, k=${VAPID_PUBLIC}`,
    },
    body,
  });
  return res.status; // 201=成功
}

/* ---------------- モデル呼び出し（Claude / GPT） ---------------- */
async function askModel(model, system, prompt, maxTokens, env) {
  if (model.startsWith("gpt")) return askGPT(model, system, prompt, maxTokens, env);
  if (model.startsWith("gemini")) return askGemini(model, system, prompt, maxTokens, env);
  if (model.startsWith("grok")) return askGrok(model, system, prompt, maxTokens, env);
  return askClaude(model, system, prompt, maxTokens, env);
}
async function askGemini(model, system, prompt, maxTokens, env) {
  if (!env.GEMINI_API_KEY) throw new Error("GEMINI_API_KEYが未設定です");
  const body = { contents: [{ role: "user", parts: [{ text: prompt }] }], generationConfig: { maxOutputTokens: maxTokens } };
  if (system) body.systemInstruction = { parts: [{ text: system }] };
  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${env.GEMINI_API_KEY}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error ? data.error.message : res.status);
  if (!data.candidates || !data.candidates[0]) throw new Error("Gemini応答が不正");
  return data.candidates[0].content.parts.map((p) => p.text).join("").trim();
}
async function askGrok(model, system, prompt, maxTokens, env) {
  if (!env.XAI_API_KEY) throw new Error("XAI_API_KEYが未設定です");
  const msgs = system ? [{ role: "system", content: system }, { role: "user", content: prompt }] : [{ role: "user", content: prompt }];
  const res = await fetch("https://api.x.ai/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + env.XAI_API_KEY },
    body: JSON.stringify({ model, messages: msgs, max_tokens: maxTokens }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error ? (data.error.message || JSON.stringify(data.error)) : res.status);
  if (!data.choices || !data.choices[0]) throw new Error("Grok応答が不正");
  return data.choices[0].message.content.trim();
}
async function askGPT(model, system, prompt, maxTokens, env) {
  if (!env.OPENAI_API_KEY) throw new Error("OPENAI_API_KEYが未設定です");
  const msgs = system ? [{ role: "system", content: system }, { role: "user", content: prompt }] : [{ role: "user", content: prompt }];
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + env.OPENAI_API_KEY },
    body: JSON.stringify({ model, messages: msgs, max_completion_tokens: maxTokens }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error ? data.error.message : res.status);
  if (!data.choices || !data.choices[0]) throw new Error("OpenAI応答が不正");
  return data.choices[0].message.content.trim();
}
async function askClaude(model, system, prompt, maxTokens, env) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "x-api-key": env.ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({ model, max_tokens: maxTokens, system, messages: [{ role: "user", content: prompt }] }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error ? data.error.message : res.status);
  return data.content.filter((b) => b.type === "text").map((b) => b.text).join("\n").trim();
}

/* ---------------- 自発メッセージ生成 ---------------- */
function nowJST() {
  return new Date(Date.now() + 9 * 3600 * 1000);
}
function jstStr(d) {
  const days = ["日", "月", "火", "水", "木", "金", "土"];
  return `${d.getUTCFullYear()}年${d.getUTCMonth() + 1}月${d.getUTCDate()}日（${days[d.getUTCDay()]}）${d.getUTCHours()}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
}

async function generateFor(char, config, env, reason) {
  const d = nowJST();
  const sys = (char.os || "") +
    `\n\n【状況】いまは ${jstStr(d)}。これはあなたから${config.userName || "相手"}に自発的に送るLINE風メッセージ。` +
    `相手はまだ返信していない。短く自然に（1〜3文程度）。前置きや説明は書かず、メッセージ本文だけを出力する。` +
    (char.memo ? `\n\n【最近のこと・覚えていること】\n${char.memo}` : "");
  const prompt = reason || "いまの時間帯に合った、あなたらしい一言を送って。";
  return askModel(char.model || "claude-sonnet-4-6", sys, prompt, 300, env);
}

async function deliver(char, text, env) {
  // 受信箱に保存
  const inbox = JSON.parse((await env.MM_KV.get("inbox")) || "[]");
  inbox.push({ char: char.name, text, ts: Date.now() });
  await env.MM_KV.put("inbox", JSON.stringify(inbox.slice(-100)));
  // プッシュ通知
  const subRaw = (await env.MM_KV.get("sub_makemarry")) || (await env.MM_KV.get("sub"));
  if (subRaw) {
    try {
      const status = await sendPush(JSON.parse(subRaw), { title: char.name, body: text }, env);
      return { pushed: status };
    } catch (e) {
      return { pushed: "error: " + e.message };
    }
  }
  return { pushed: "no-subscription" };
}

/* ---------------- cron本体 ---------------- */
async function runCron(env, force) {
  const config = JSON.parse((await env.MM_KV.get("config")) || "null");
  if (!config || !config.chars || !config.chars.length) return { note: "config未設定" };
  const state = JSON.parse((await env.MM_KV.get("state")) || "{}");
  const d = nowJST();
  const hour = d.getUTCHours();
  const today = `${d.getUTCFullYear()}-${d.getUTCMonth() + 1}-${d.getUTCDate()}`;
  const results = [];

  for (const char of config.chars) {
    // 1キャラのエラーが他キャラに波及しないよう、キャラ単位で完全に分離する
    try {
      if (!char.auto) continue; // 自発OFFのキャラはテスト実行でも対象外
      const start = char.hourStart ?? 8;
      const end = char.hourEnd ?? 23;
      const inWindow = start <= end ? hour >= start && hour < end : hour >= start || hour < end;
      if (!inWindow && !force) continue;

      const last = state[char.name] || 0;
      const minGapMs = (char.minGapHours ?? 3) * 3600 * 1000;
      const gapOk = Date.now() - last >= minGapMs;

      // 保証枠: morningHour が設定されていれば、その時間台は未送信なら必ず送る
      const morningDue =
        char.morningHour != null &&
        hour === char.morningHour &&
        state["m_" + char.name] !== today;

      if (!force && !morningDue) {
        if (!gapOk) continue;
        const slots = ((end - start + 24) % 24 || 24) * 2;
        const p = Math.min(1, (char.perDay ?? 2) / slots);
        if (Math.random() > p) continue;
      }

      const reason = morningDue
        ? "朝の時間帯です。今日最初の、あなたらしい朝のメッセージを送って。"
        : null;
      const text = await generateFor(char, config, env, reason);
      const r = await deliver(char, text, env);
      state[char.name] = Date.now();
      if (morningDue) state["m_" + char.name] = today;
      results.push({ char: char.name, text, morning: !!morningDue, ...r });
    } catch (e) {
      results.push({ char: char.name, error: String(e.message || e) });
      continue; // 次のキャラへ
    }
  }
  await env.MM_KV.put("state", JSON.stringify(state));
  const silResults = await runSilSched(env);
  return { ran: true, results: results.concat(silResults) };
}

async function runSilSched(env) {
  const out = [];
  try {
    const schedRaw = await env.MM_KV.get("sil_sched");
    if (!schedRaw) return out;
    const items = JSON.parse(schedRaw);
    const silSub = await env.MM_KV.get("sub_silente");
    let changed = false;
    for (const it of items) {
      if (it.n) continue;
      if (new Date(it.at).getTime() <= Date.now()) {
        it.n = 1; changed = true;
        if (silSub) {
          try {
            await sendPush(JSON.parse(silSub), { title: "⏰ " + (it.note || "約束の時間"), body: "約束の時間だよ。開くと届く。", url: "./" }, env);
            out.push({ silente: it.note, pushed: 201 });
          } catch (e) { out.push({ silente: it.note, error: e.message }); }
        }
      }
    }
    if (changed) await env.MM_KV.put("sil_sched", JSON.stringify(items));
  } catch (e) { out.push({ silente: "sched-error", error: String(e.message || e) }); }
  return out;
}

/* ---------------- HTTP ---------------- */
export default {
  async scheduled(event, env, ctx) {
    // 5分刻みのトリガーはSilente予定通知だけを担当、30分刻みは全部
    if (event.cron && event.cron.includes("/5")) {
      ctx.waitUntil(runSilSched(env));
    } else {
      ctx.waitUntil(runCron(env, false));
    }
  },

  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return json({});
    const path = url.pathname;

    if (path === "/" ) {
      const sub = await env.MM_KV.get("sub");
      const config = await env.MM_KV.get("config");
      const inbox = JSON.parse((await env.MM_KV.get("inbox")) || "[]");
      return json({ ok: true, app: "Makemarry Server", subscribed: !!sub, configured: !!config, inboxCount: inbox.length });
    }
    if (path === "/public-key") return json({ key: VAPID_PUBLIC });

    // ここから下はトークン必須
    const token = req.headers.get("x-mm-token") || url.searchParams.get("token");
    if (token !== env.MM_TOKEN) return json({ error: "認証エラー（トークン不一致）" }, 401);

    if (path === "/subscribe" && req.method === "POST") {
      const body = await req.json();
      const app = body.app === "silente" ? "silente" : "makemarry";
      await env.MM_KV.put("sub_" + app, JSON.stringify(body.subscription));
      if (app === "makemarry") await env.MM_KV.put("sub", JSON.stringify(body.subscription));
      return json({ ok: true, app });
    }
    if (path === "/silente-sched" && req.method === "POST") {
      const body = await req.json();
      await env.MM_KV.put("sil_sched", JSON.stringify(body.items || []));
      return json({ ok: true, count: (body.items || []).length });
    }
    if (path === "/config" && req.method === "POST") {
      const body = await req.json();
      await env.MM_KV.put("config", JSON.stringify(body));
      return json({ ok: true, chars: (body.chars || []).length });
    }
    if (path === "/shared") {
      const config = JSON.parse((await env.MM_KV.get("config")) || "null");
      return json(config && config.shared ? config.shared : { error: "共有データ未同期" });
    }
    if (path === "/inbox") {
      const inbox = JSON.parse((await env.MM_KV.get("inbox")) || "[]");
      if (url.searchParams.get("clear") === "1") await env.MM_KV.put("inbox", "[]");
      return json({ messages: inbox });
    }
    if (path === "/test-push") {
      const app = url.searchParams.get("app") === "silente" ? "sub_silente" : null;
      const subRaw = app ? await env.MM_KV.get(app) : ((await env.MM_KV.get("sub_makemarry")) || (await env.MM_KV.get("sub")));
      if (!subRaw) return json({ error: "購読が未登録です。アプリから接続してください" }, 400);
      const status = await sendPush(JSON.parse(subRaw), { title: "Makemarry", body: "サーバーからのテスト通知や。届いてるで。" }, env);
      return json({ pushed: status });
    }
    if (path === "/debug") {
      const config = JSON.parse((await env.MM_KV.get("config")) || "null");
      const state = JSON.parse((await env.MM_KV.get("state")) || "{}");
      const sched = JSON.parse((await env.MM_KV.get("sil_sched")) || "[]");
      if (!config) return json({ error: "config未設定（アプリで同期を押して）" });
      const d = nowJST();
      const hour = d.getUTCHours();
      const chars = (config.chars || []).map((c) => {
        const start = c.hourStart ?? 8, end = c.hourEnd ?? 23;
        const inWindow = start <= end ? hour >= start && hour < end : hour >= start || hour < end;
        const last = state[c.name] || 0;
        const gapLeftMin = Math.max(0, Math.round(((c.minGapHours ?? 3) * 3600000 - (Date.now() - last)) / 60000));
        const slots = ((end - start + 24) % 24 || 24) * 2;
        return {
          name: c.name, auto: !!c.auto, model: c.model,
          時間帯: start + "時〜" + end + "時", いま時間内: inWindow,
          最終送信: last ? new Date(last + 9 * 3600000).toISOString().slice(5, 16).replace("T", " ") : "なし",
          あと何分で送信可能: gapLeftMin,
          "1回あたりの当選率": Math.round(Math.min(1, (c.perDay ?? 2) / slots) * 1000) / 10 + "%",
          朝の保証枠: c.morningHour != null ? c.morningHour + "時台" : "なし",
        };
      });
      return json({ 現在時刻JST: jstStr(d), chars, silente予定: sched });
    }
    if (path === "/debug") {
      const config = JSON.parse((await env.MM_KV.get("config")) || "null");
      const state = JSON.parse((await env.MM_KV.get("state")) || "{}");
      const d = nowJST();
      const hour = d.getUTCHours();
      if (!config || !config.chars) return json({ error: "config未設定。アプリで同期を押して" });
      const rows = config.chars.map((char) => {
        const start = char.hourStart ?? 8, end = char.hourEnd ?? 23;
        const inWindow = start <= end ? hour >= start && hour < end : hour >= start || hour < end;
        const last = state[char.name] || 0;
        const gapMin = last ? Math.round((Date.now() - last) / 60000) : null;
        const gapOk = Date.now() - last >= (char.minGapHours ?? 3) * 3600 * 1000;
        const slots = ((end - start + 24) % 24 || 24) * 2;
        const p = Math.min(1, (char.perDay ?? 2) / slots);
        return {
          name: char.name, auto: !!char.auto, morningHour: char.morningHour ?? null,
          時間帯: start + "時〜" + end + "時", いまJST: hour + "時", 時間帯内: inWindow,
          前回送信からの分: gapMin, 間隔OK: gapOk,
          毎回の当選率: Math.round(p * 1000) / 10 + "%",
          判定: !char.auto ? "❌自発OFF" : !inWindow ? "❌時間帯外" : !gapOk ? "❌間隔待ち" : "🎲抽選対象",
        };
      });
      const sched = JSON.parse((await env.MM_KV.get("sil_sched")) || "[]");
      return json({ いまJST: jstStr(d), chars: rows, silente予定: sched });
    }
    if (path === "/run") {
      // 手動でcronロジックを即実行（テスト用・確率無視）
      const r = await runCron(env, true);
      return json(r);
    }
    return json({ error: "not found" }, 404);
  },
};
