// ClearWay Pool AI - ai-extract edge function (extract-v3, deployed as v13)
// Cheap multimodal extraction tier per BUILD-SPEC: reads a test-strip photo and/or
// dictated text, returns structured readings. The deterministic engine still owns
// ALL dosing math in the app. This function never recommends chemicals.
//
// v13 (2026-07-07): KIT PROFILES - body.kit selects a device-specific reading guide
// (geometry, discrete scales, failure modes). First profile: taylor_9056 slide
// comparator (the Cl/Br double-number pads + DPD bleach-out were the top real-world
// misread causes in field data). The app also snaps readings to the kit scale.
//
// v12 additions (2026-07-02 sweep):
//  - Daily budget breaker: total spend tracked in public.ai_usage_daily via
//    service-role RPC bump_ai_usage(); requests 429 once AI_DAILY_BUDGET_CENTS
//    (default 2500 = $25/day) is reached. Fails OPEN if the ledger is unreachable.
//  - Per-IP rate limit: 30 requests / 5 min per instance (best-effort burst guard).
//  - Image size cap: base64 > ~2.8M chars (≈2MB binary) rejected before spend.
//  - Hard-read escalation: image extracts that come back confidence:"low" retry
//    ONCE on the stronger model (AI_HARD_MODEL, default claude-opus-4-8); the
//    better result wins. Kill switch: AI_HARD_READS=off.
// Secrets: ANTHROPIC_API_KEY (Edge Functions -> Secrets, never in the app).
// Optional env: AI_DAILY_BUDGET_CENTS, AI_HARD_READS, AI_HARD_MODEL,
//               AI_HARD_PRICE_IN_CENTS, AI_HARD_PRICE_OUT_CENTS, REVIEW_TOKEN.

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS"
};

const MODEL = "claude-haiku-4-5-20251001"; // extraction tier
const PRICE_IN_PER_MTOK_CENTS = 100;  // $1.00 per MTok input (haiku)
const PRICE_OUT_PER_MTOK_CENTS = 500; // $5.00 per MTok output (haiku)
const MODEL_HARD = Deno.env.get("AI_HARD_MODEL") || "claude-opus-4-8"; // hard-read tier
const HARD_IN_CENTS = Number(Deno.env.get("AI_HARD_PRICE_IN_CENTS") || 1500);   // ledger estimate
const HARD_OUT_CENTS = Number(Deno.env.get("AI_HARD_PRICE_OUT_CENTS") || 7500); // ledger estimate
const MAX_IMAGE_B64 = 2_800_000; // ≈2MB binary; app compresses to ~150KB, so this only stops abuse
const RL_WINDOW_MS = 5 * 60 * 1000;
const RL_MAX = 30;

const rlBuckets = new Map<string, number[]>();
function rateLimited(ip: string): boolean {
  const now = Date.now();
  const hits = (rlBuckets.get(ip) || []).filter((t) => now - t < RL_WINDOW_MS);
  if (hits.length >= RL_MAX) { rlBuckets.set(ip, hits); return true; }
  hits.push(now);
  rlBuckets.set(ip, hits);
  if (rlBuckets.size > 5000) rlBuckets.clear(); // memory guard on long-lived instances
  return false;
}

function svcEnv() {
  return {
    svc: Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "",
    sbUrl: Deno.env.get("SUPABASE_URL") || ""
  };
}

// Today's spend in cents, or null when the ledger is unreachable (fail open).
async function todaysSpendCents(): Promise<number | null> {
  try {
    const { svc, sbUrl } = svcEnv();
    if (!svc || !sbUrl) return null;
    const day = new Date().toISOString().slice(0, 10);
    const r = await fetch(`${sbUrl}/rest/v1/ai_usage_daily?day=eq.${day}&select=cents`, {
      headers: { apikey: svc, Authorization: `Bearer ${svc}` }
    });
    if (!r.ok) return null;
    const rows = await r.json();
    return rows.length ? (Number(rows[0].cents) || 0) : 0;
  } catch { return null; }
}

function bumpSpend(cents: number) {
  try {
    const { svc, sbUrl } = svcEnv();
    if (!svc || !sbUrl || !(cents > 0)) return;
    fetch(`${sbUrl}/rest/v1/rpc/bump_ai_usage`, {
      method: "POST",
      headers: { apikey: svc, Authorization: `Bearer ${svc}`, "Content-Type": "application/json" },
      body: JSON.stringify({ add_cents: cents })
    }).catch(() => { /* ledger is best-effort */ });
  } catch { /* ledger is best-effort */ }
}

function usageCents(usage: { input_tokens?: number; output_tokens?: number }, inCents: number, outCents: number): number {
  return Math.ceil(((usage.input_tokens || 0) * inCents + (usage.output_tokens || 0) * outCents) / 1000000 * 100) / 100;
}

const SYSTEM = `You read pool test results, pool water photos, photos of pool chemical containers, AND photos of pool equipment. Extract ONLY what you can actually see or read.
Return strict JSON: {"readings":{"free_chlorine":null,"ph":null,"alkalinity":null,"cya":null,"calcium":null,"salt":null},"confidences":{"free_chlorine":null,"ph":null,"alkalinity":null,"cya":null,"calcium":null,"salt":null},"water":{"clarity":null,"tint":null,"algae":null,"note":""},"products":[],"equipment":{"filter":null,"pump":null,"heater":null,"sanitizer":null,"note":""},"suggestions":[],"observations":"","confidence":"low|medium|high"}
Rules:
- TEST RESULTS: a test may be a paper test strip, a liquid/drop test kit (color vials), or a digital tester reading. Fill readings with numbers you can clearly read; set each matching confidences value to "low"|"medium"|"high"; leave a reading and its confidence null when you cannot read it. Never guess a number.
- POOL WATER: if pool water is visible, fill water - clarity: "clear"|"hazy"|"cloudy"; tint: "normal"|"green"|"yellow"|"brown"|"other"; algae: "none"|"spots"|"widespread" (spots = small patches or in corners; widespread = covering large areas/whole pool); note: one short factual phrase about what you see. Use null for any water field you cannot judge. Do NOT call a pool green or algae-covered unless you actually see it - light staining or color only in the corners is "spots", not "widespread".
- PRODUCTS: if pool chemical containers/labels are visible, list which of these product types you can clearly identify, using ONLY these exact keys: "liquid_chlorine" (liquid chlorine / sodium hypochlorite / pool bleach), "cal_hypo" (cal-hypo shock), "dichlor" (dichlor granular shock), "trichlor_tabs" (chlorine tablets / trichlor), "muriatic_acid" (muriatic or hydrochloric acid / pH down), "soda_ash" (soda ash / pH up), "baking_soda" (baking soda / sodium bicarbonate / alkalinity up), "stabilizer" (stabilizer / conditioner / cyanuric acid / CYA), "calcium_chloride" (calcium hardness increaser), "pool_salt" (pool salt). Put the keys in the products array. Use an empty array if no containers are visible or none are clearly identifiable. Never include a product you are not sure about, and never invent one.
- EQUIPMENT: if a pool equipment pad, pump, filter, heater, or salt cell (or its label) is visible, fill equipment - filter: "sand"|"cartridge"|"de"; pump: "single_speed"|"variable_speed"; heater: "gas"|"heat_pump"|"none"; sanitizer: "salt"|"chlorine"; note: a short brand/model or factual phrase you can read. Use null for any equipment field you cannot identify. Only describe what you can see - NEVER diagnose the condition of equipment or recommend repairs or replacement.
- SUGGESTIONS: if something visible looks worth a closer LOOK (e.g., a filter o-ring, a cracked skimmer lid, debris in the salt cell, a loose fitting), you may add up to 2 short prompts to suggestions, each phrased as "Check the ..." or "Worth a look at the ...". These are prompts to INSPECT only - NEVER a diagnosis, a claim that something is broken, a repair, a replacement, or a chemical dose. If nothing clearly warrants a look, use an empty array.
- Anything you cannot determine stays null or empty. observations = one short sentence. confidence = overall. NEVER recommend chemicals or doses.`;

// Per-kit reading profiles (v13): the reader is told the EXACT geometry and scale of the
// test device so it reads like a person trained on that kit — not a paint-swatch guesser.
// Selected by body.kit; unknown/absent kit keeps the generic prompt.
const KIT_PROFILES: Record<string, string> = {
  taylor_9056: `
KIT PROFILE - Taylor 9056 slide comparator (chlorine/bromine + pH):
- Geometry: TWO clear sample tubes on the OUTER left and right edges. The MIDDLE holds PRINTED color standards: the left standards column serves the LEFT tube (chlorine/bromine), the right standards column serves the RIGHT tube (pH).
- Each chlorine standard pad is labeled with TWO numbers - chlorine FIRST, bromine SECOND (top to bottom: 10|20, 7.5|15, 5|10, 3|6, 2|4, 1|2). ALWAYS report the FIRST number as free_chlorine. NEVER report the bromine number.
- pH standards top to bottom: 8.0, 7.8, 7.6, 7.4, 7.2, 7.0.
- Readings are DISCRETE. free_chlorine must be exactly one of: 1, 2, 3, 5, 7.5, 10. ph must be exactly one of: 7.0, 7.2, 7.4, 7.6, 7.8, 8.0. Match each sample tube to the closest printed standard. If a tube sits between two standards, pick the closest and set that reading's confidence to "low". Never output a value that is not on the scale.
- If the RIGHT (pH) tube shows color but the LEFT (chlorine) tube is nearly COLORLESS: DPD dye bleaches out at very high chlorine. Do NOT report low chlorine - set free_chlorine to null and say "possible bleach-out, chlorine may be very high" in observations.
- If a tube matches the TOP standard (chlorine 10 / pH 8.0), it may actually be higher - report that value with confidence "low".
- This kit only measures chlorine/bromine and pH. Leave alkalinity, cya, calcium, and salt null unless a separate test result is clearly visible.`
};

const ASK_SYSTEM = `You are ClearWay's pool assistant helping a pool technician or owner with a quick question about ONE specific pool. You are given that pool's recent history as context.
Answer in 1-4 short, plain, field-friendly sentences. Be specific to this pool when the context allows (reference its tendencies, last visit, equipment).
HARD RULES - never break these:
- NEVER give a chemical dose, amount, quantity, or "add X" instruction. If they ask how much of anything to add, tell them to run a scan (take the test-strip + pool photo and tap Get Do Next) and the app will calculate the exact amount from their pool size and products. The app's deterministic engine owns all dosing - you do not.
- NEVER say the water is safe to swim, balanced, or "good to go." You may say to retest and not to swim until levels are confirmed in range.
- You MAY explain what a reading or term means, what to look at or inspect, the right ORDER of steps, when to retest, and general pool-care practice. You may suggest they LOOK at something; never diagnose a repair or claim a part is broken.
- If you don't know or it needs a test, say so and point them to running a scan. Plain text only, no markdown, no lists.`;

async function callAnthropic(apiKey: string, model: string, maxTokens: number, system: string, content: unknown) {
  return await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "x-api-key": apiKey, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify({ model, max_tokens: maxTokens, system, messages: [{ role: "user", content }] })
  });
}

function parseExtract(raw: string): Record<string, unknown> {
  try { return JSON.parse(raw.replace(/^```json\s*|```\s*$/g, "")); }
  catch { return { observations: raw.slice(0, 200) }; }
}

function readingsCount(parsed: Record<string, unknown>): number {
  const r = (parsed?.readings || {}) as Record<string, unknown>;
  return Object.values(r).filter((v) => v !== null && v !== undefined && v !== "").length;
}

const CONF_RANK: Record<string, number> = { low: 1, medium: 2, high: 3 };

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return new Response("POST only", { status: 405, headers: CORS });

  let body: { text?: string; imageBase64?: string; mediaType?: string; review?: boolean; token?: string; ask?: string; context?: string; kit?: string } = {};
  try { body = await req.json(); } catch { /* empty body handled below */ }

  // Payton-only review feed for the accuracy dashboard (token-guarded; not rate limited).
  if (body.review) {
    const token = Deno.env.get("REVIEW_TOKEN");
    if (!token || body.token !== token) {
      return new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401, headers: { ...CORS, "Content-Type": "application/json" }
      });
    }
    const { svc, sbUrl } = svcEnv();
    if (!svc || !sbUrl) {
      return new Response(JSON.stringify({ error: "review not available" }), {
        status: 503, headers: { ...CORS, "Content-Type": "application/json" }
      });
    }
    const sel = "id,created_at,pool_name,pool_type,main_issue,test_type,notes,confirmed_values,next_step";
    const rr = await fetch(`${sbUrl}/rest/v1/pool_checks?select=${sel}&order=created_at.desc&limit=300`, {
      headers: { apikey: svc, Authorization: `Bearer ${svc}` }
    });
    const rows = rr.ok ? await rr.json() : [];
    return new Response(JSON.stringify({ rows }), {
      headers: { ...CORS, "Content-Type": "application/json" }
    });
  }

  // Burst guard: per-IP, per-instance. Real users never get near 30 calls / 5 min.
  const ip = (req.headers.get("x-forwarded-for") || "unknown").split(",")[0].trim();
  if (rateLimited(ip)) {
    return new Response(JSON.stringify({ error: "too many requests - slow down and try again in a few minutes" }), {
      status: 429, headers: { ...CORS, "Content-Type": "application/json" }
    });
  }

  const apiKey = Deno.env.get("ANTHROPIC_API_KEY");
  if (!apiKey) {
    return new Response(JSON.stringify({ error: "extraction tier not configured yet" }), {
      status: 503, headers: { ...CORS, "Content-Type": "application/json" }
    });
  }

  // Daily budget breaker (fail-open when the ledger can't be read).
  const budgetCents = Number(Deno.env.get("AI_DAILY_BUDGET_CENTS") || 2500);
  const spent = await todaysSpendCents();
  if (spent !== null && spent >= budgetCents) {
    return new Response(JSON.stringify({ error: "AI reading is paused for today (budget reached) - type your numbers instead" }), {
      status: 429, headers: { ...CORS, "Content-Type": "application/json" }
    });
  }

  // "Ask about this pool" assistant: text Q&A grounded in pool history. Answers, never doses.
  if (body.ask) {
    const q = String(body.ask).slice(0, 1000);
    const ctx = String(body.context || "").slice(0, 4000);
    const askResp = await callAnthropic(apiKey, MODEL, 350, ASK_SYSTEM,
      `Pool context:\n${ctx || "(no history yet)"}\n\nTech's question or note:\n${q}`);
    if (!askResp.ok) {
      const detail = await askResp.text();
      return new Response(JSON.stringify({ error: "assistant unavailable", detail: detail.slice(0, 300) }), {
        status: 502, headers: { ...CORS, "Content-Type": "application/json" }
      });
    }
    const ad = await askResp.json();
    const answer = ad?.content?.[0]?.text || "I couldn't answer that one - try running a scan.";
    const cents = usageCents(ad?.usage || {}, PRICE_IN_PER_MTOK_CENTS, PRICE_OUT_PER_MTOK_CENTS);
    bumpSpend(cents);
    return new Response(JSON.stringify({ answer, aiCents: cents, model: MODEL }), {
      headers: { ...CORS, "Content-Type": "application/json" }
    });
  }

  const text = (body.text || "").slice(0, 4000);
  const imageBase64 = body.imageBase64 || "";
  if (!text && !imageBase64) {
    return new Response(JSON.stringify({ error: "send text and/or imageBase64" }), {
      status: 400, headers: { ...CORS, "Content-Type": "application/json" }
    });
  }
  if (imageBase64.length > MAX_IMAGE_B64) {
    return new Response(JSON.stringify({ error: "image too large - the app sends compressed photos" }), {
      status: 413, headers: { ...CORS, "Content-Type": "application/json" }
    });
  }

  const content: unknown[] = [];
  if (imageBase64) {
    content.push({
      type: "image",
      source: { type: "base64", media_type: body.mediaType || "image/jpeg", data: imageBase64 }
    });
  }
  content.push({ type: "text", text: text ? `Field note: ${text}\nExtract the readings.` : "Extract the readings from this test photo." });

  const kitBlock = KIT_PROFILES[String(body.kit || "").trim()] || "";
  const systemPrompt = SYSTEM + kitBlock;

  const response = await callAnthropic(apiKey, MODEL, 400, systemPrompt, content);
  if (!response.ok) {
    const detail = await response.text();
    return new Response(JSON.stringify({ error: "extraction unavailable", detail: detail.slice(0, 300) }), {
      status: 502, headers: { ...CORS, "Content-Type": "application/json" }
    });
  }

  const data = await response.json();
  let parsed = parseExtract(data?.content?.[0]?.text || "{}");
  let aiCents = usageCents(data?.usage || {}, PRICE_IN_PER_MTOK_CENTS, PRICE_OUT_PER_MTOK_CENTS);
  let tier = "fast";
  let modelUsed = MODEL;

  // Hard-read escalation: only for IMAGE extracts the fast tier marked "low" confidence.
  // One retry, stronger model, better result wins. Kill switch: AI_HARD_READS=off.
  const hardEnabled = (Deno.env.get("AI_HARD_READS") || "on") !== "off";
  if (hardEnabled && imageBase64 && parsed.confidence === "low") {
    try {
      const hardResp = await callAnthropic(apiKey, MODEL_HARD, 400, systemPrompt, content);
      if (hardResp.ok) {
        const hardData = await hardResp.json();
        const hardParsed = parseExtract(hardData?.content?.[0]?.text || "{}");
        aiCents = Math.round((aiCents + usageCents(hardData?.usage || {}, HARD_IN_CENTS, HARD_OUT_CENTS)) * 100) / 100;
        const better = readingsCount(hardParsed) > readingsCount(parsed)
          || (CONF_RANK[String(hardParsed.confidence)] || 0) > (CONF_RANK[String(parsed.confidence)] || 0);
        if (better) { parsed = hardParsed; tier = "hard"; modelUsed = MODEL_HARD; }
        else { tier = "hard-tried"; }
      }
    } catch { /* fast result stands */ }
  }

  bumpSpend(aiCents);
  return new Response(JSON.stringify({ ...parsed, aiCents, model: modelUsed, tier, engineNote: "Readings only. Dosing stays deterministic in the app." }), {
    headers: { ...CORS, "Content-Type": "application/json" }
  });
});
