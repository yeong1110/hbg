import { Hono, type Context } from "hono";
import { setCookie, getCookie } from "hono/cookie";
import {
  botContextRequestSchema, crossedThreshold, generateAnalysis, patchSectionCodes,
  reportSchema, reproductionBand, reproductionSchema, resolutionLabels, statusRequestSchema,
} from "@hbc/shared";

type RateLimiter = { limit(input: { key: string }): Promise<{ success: boolean }> };
type Env = {
  DB: D1Database; ASSETS: Fetcher;
  ENVIRONMENT: string; PUBLIC_WRITE_MODE: string; PUBLIC_ORIGIN: string;
  VISITOR_HASH_SECRET: string; BOT_CONTEXT_SECRET: string;
  TURNSTILE_REPORT_SECRET: string; TURNSTILE_REPRODUCE_SECRET: string;
  TURNSTILE_EXPECTED_HOSTNAME: string;
  TURNSTILE_REPORT_SITE_KEY: string; TURNSTILE_REPRODUCE_SITE_KEY: string;
  REPORT_GLOBAL: RateLimiter; REPORT_VISITOR: RateLimiter; REPRO_GLOBAL: RateLimiter; REPRO_VISITOR: RateLimiter;
  READ_GLOBAL: RateLimiter; READ_VISITOR: RateLimiter; STATUS_GLOBAL: RateLimiter; STATUS_VISITOR: RateLimiter;
  CONTEXT_GLOBAL: RateLimiter; CONTEXT_VISITOR: RateLimiter;
};
type Vars = { visitorId: string; visitorHash: string; requestId: string };
type Bindings = { Bindings: Env; Variables: Vars };
type BotPurpose = "report" | "reproduce";
type BotPayload = { v: 1; p: BotPurpose; vh: string; cn?: string; iat: number; exp: number; n: string };

const app = new Hono<Bindings>();
type AppContext = Context<Bindings>;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const maxJsonBytes = 16 * 1024;
const emailPattern = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;
const phonePattern = /(?:01[016789])[-.\s]?\d{3,4}[-.\s]?\d{4}/;

function jsonData<T>(c: AppContext, data: T, status = 200) {
  return c.json({ data, error: null, requestId: c.get("requestId") }, status as any);
}
function jsonError(c: AppContext, status: number, code: string, message: string, headers?: Record<string, string>) {
  const response = c.json({ data: null, error: { code, message }, requestId: c.get("requestId") }, status as any);
  if (headers) Object.entries(headers).forEach(([k, v]) => response.headers.set(k, v));
  return response;
}
function randomBase64Url(bytes = 16) { const value = crypto.getRandomValues(new Uint8Array(bytes)); return btoa(String.fromCharCode(...value)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", ""); }
function toBase64Url(value: Uint8Array) { return btoa(String.fromCharCode(...value)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", ""); }
function fromBase64Url(value: string) { const raw = atob(value.replaceAll("-", "+").replaceAll("_", "/")); return Uint8Array.from(raw, x => x.charCodeAt(0)); }
async function sha256(value: string | Uint8Array) { const bytes = typeof value === "string" ? encoder.encode(value) : value; return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource))].map(x => x.toString(16).padStart(2, "0")).join(""); }
async function hmac(secret: string, value: string) { const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value))); }
async function signContext(env: Env, payload: BotPayload) { const body = toBase64Url(encoder.encode(JSON.stringify(payload))); return `${body}.${toBase64Url(await hmac(env.BOT_CONTEXT_SECRET, body))}`; }
async function verifyContext(env: Env, token: string, purpose: BotPurpose, visitorHash: string, caseNumber?: string) {
  const [body, signature, extra] = token.split("."); if (!body || !signature || extra) return false;
  const expected = await hmac(env.BOT_CONTEXT_SECRET, body); const supplied = fromBase64Url(signature); let diff = supplied.length ^ expected.length; for (let i = 0; i < expected.length; i++) diff |= (supplied[i] ?? 0) ^ expected[i]!; if (diff !== 0) return false;
  try {
    const payload = JSON.parse(decoder.decode(fromBase64Url(body))) as BotPayload; const now = Date.now(); const minAge = purpose === "report" ? 3000 : 750;
    return payload.v === 1 && payload.p === purpose && payload.vh === visitorHash.slice(0, 24) && payload.cn === caseNumber && now >= payload.iat + minAge && now <= payload.exp;
  } catch { return false; }
}

async function applyRateLimit(c: AppContext, limiter: RateLimiter | undefined, key: string) {
  if (!limiter || c.env.ENVIRONMENT === "local") return true;
  return (await limiter.limit({ key })).success;
}
async function requireLimits(c: AppContext, global: keyof Env, visitor: keyof Env) {
  const globalOk = await applyRateLimit(c, c.env[global] as RateLimiter, "route");
  const visitorOk = globalOk && await applyRateLimit(c, c.env[visitor] as RateLimiter, c.get("visitorHash"));
  if (!visitorOk) return jsonError(c, 429, "RATE_LIMITED", "요청이 너무 빠릅니다. 60초 후 다시 시도하십시오.", { "Retry-After": "60" });
  return null;
}
async function parseJson(c: AppContext) {
  const type = c.req.header("content-type") ?? ""; const length = Number(c.req.header("content-length") ?? 0);
  if (!type.startsWith("application/json") || length > maxJsonBytes) throw new Error("INVALID_BODY");
  const text = await c.req.text(); if (encoder.encode(text).byteLength > maxJsonBytes) throw new Error("INVALID_BODY");
  return JSON.parse(text) as unknown;
}
function requireOrigin(c: AppContext) { const origin = c.req.header("origin"); return !origin || origin === c.env.PUBLIC_ORIGIN || (c.env.ENVIRONMENT === "local" && /^http:\/\/localhost:\d+$/.test(origin)); }
async function verifyTurnstile(env: Env, token: string, purpose: BotPurpose, idempotencyKey: string) {
  if (env.ENVIRONMENT === "local" && token.startsWith("XXXX.DUMMY.TOKEN")) return true;
  const secret = purpose === "report" ? env.TURNSTILE_REPORT_SECRET : env.TURNSTILE_REPRODUCE_SECRET; if (!secret) return false;
  const body = new URLSearchParams({ secret, response: token, idempotency_key: idempotencyKey });
  const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body });
  const data = await response.json() as { success: boolean; hostname?: string; action?: string };
  return data.success && data.hostname === env.TURNSTILE_EXPECTED_HOSTNAME && data.action === purpose;
}
function isoNow() { return new Date().toISOString(); }
function normalizeContent(values: { title: string; reproductionSteps: string; expectedResult: string; actualResult: string }) { return [values.title, values.reproductionSteps, values.expectedResult, values.actualResult].map(x => x.normalize("NFKC").trim().replace(/\s+/g, " ").toLowerCase()).join("|"); }
function makeCaseNumber() { const date = new Date().toISOString().slice(2, 10).replaceAll("-", ""); const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; const bytes = crypto.getRandomValues(new Uint8Array(6)); return `HBC-${date}-${[...bytes].map(x => alphabet[x % alphabet.length]).join("")}`; }
function safeMetadata(value: unknown) { return JSON.stringify(value).slice(0, 1000); }

app.use("*", async (c, next) => {
  const requestId = crypto.randomUUID(); c.set("requestId", requestId);
  const existing = getCookie(c, "__Host-hbc_vid") ?? getCookie(c, "hbc_vid"); const visitorId = existing && /^[A-Za-z0-9_-]{20,30}$/.test(existing) ? existing : randomBase64Url(16);
  c.set("visitorId", visitorId); c.set("visitorHash", await sha256(`${c.env.VISITOR_HASH_SECRET}:${visitorId}`));
  if (!existing) setCookie(c, c.env.ENVIRONMENT === "local" ? "hbc_vid" : "__Host-hbc_vid", visitorId, { httpOnly: true, secure: c.env.ENVIRONMENT !== "local", sameSite: "Lax", path: "/", maxAge: 31536000 });
  await next();
  c.header("X-Request-Id", requestId); c.header("X-Content-Type-Options", "nosniff"); c.header("Referrer-Policy", "strict-origin-when-cross-origin"); c.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  c.header("Content-Security-Policy", "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'");
});

app.get("/api/v1/health", c => jsonData(c, { ok: true, version: "0.1.0" }));
app.get("/api/v1/config", c => jsonData(c, {
  turnstileReportSiteKey: c.env.TURNSTILE_REPORT_SITE_KEY,
  turnstileReproduceSiteKey: c.env.TURNSTILE_REPRODUCE_SITE_KEY,
}));
app.post("/api/v1/bot-context", async c => {
  if (!requireOrigin(c)) return jsonError(c, 403, "ORIGIN_REJECTED", "요청 출처를 확인할 수 없습니다.");
  const limited = await requireLimits(c, "CONTEXT_GLOBAL", "CONTEXT_VISITOR"); if (limited) return limited;
  let raw: unknown; try { raw = await parseJson(c); } catch { return jsonError(c, 400, "INVALID_BODY", "요청 형식이 올바르지 않습니다."); }
  const parsed = botContextRequestSchema.safeParse(raw); if (!parsed.success) return jsonError(c, 400, "INVALID_BODY", "요청 형식이 올바르지 않습니다.");
  const now = Date.now(); const payload: BotPayload = { v: 1, p: parsed.data.purpose, vh: c.get("visitorHash").slice(0, 24), cn: parsed.data.caseNumber, iat: now, exp: now + 30 * 60_000, n: randomBase64Url(12) };
  return jsonData(c, { token: await signContext(c.env, payload), expiresAt: new Date(payload.exp).toISOString() });
});

app.post("/api/v1/submissions", async c => {
  if (c.env.PUBLIC_WRITE_MODE !== "enabled") return jsonError(c, 503, "WRITES_DISABLED", "현재 신규 접수 업무가 일시 중단되었습니다.");
  if (!requireOrigin(c)) return jsonError(c, 403, "ORIGIN_REJECTED", "요청 출처를 확인할 수 없습니다.");
  const limited = await requireLimits(c, "REPORT_GLOBAL", "REPORT_VISITOR"); if (limited) return limited;
  let raw: unknown; try { raw = await parseJson(c); } catch { return jsonError(c, 400, "INVALID_BODY", "요청 형식이 올바르지 않습니다."); }
  const parsed = reportSchema.safeParse(raw); if (!parsed.success) return jsonError(c, 400, "INVALID_REPORT", "필수 신고 항목을 확인하십시오."); const report = parsed.data;
  if (report.website || !await verifyContext(c.env, report.botContext, "report", c.get("visitorHash"))) return jsonError(c, 400, "REQUEST_REJECTED", "요청을 확인할 수 없습니다. 페이지를 새로 열어 다시 시도하십시오.");
  const allText = `${report.title}\n${report.reproductionSteps}\n${report.expectedResult}\n${report.actualResult}\n${report.environment}`;
  if (emailPattern.test(allText) || phonePattern.test(allText)) return jsonError(c, 400, "PERSONAL_DATA_DETECTED", "이메일 또는 전화번호로 보이는 내용을 삭제하십시오.");
  if (!await verifyTurnstile(c.env, report.turnstileToken, "report", report.submissionRequestId)) return jsonError(c, 403, "BOT_VERIFICATION_FAILED", "사람 확인에 실패했습니다. 다시 시도하십시오.");
  const dayAgo = new Date(Date.now() - 86_400_000).toISOString(); const fingerprint = await sha256(`${c.env.VISITOR_HASH_SECRET}:${normalizeContent(report)}`);
  const prior = await c.env.DB.prepare("SELECT COUNT(*) AS count, MAX(CASE WHEN content_fingerprint = ? THEN 1 ELSE 0 END) AS duplicate FROM cases WHERE submitter_hash = ? AND created_at >= ?").bind(fingerprint, c.get("visitorHash"), dayAgo).first<{ count: number; duplicate: number }>();
  if ((prior?.count ?? 0) >= 5) return jsonError(c, 429, "DAILY_REPORT_LIMIT", "이 브라우저의 일일 접수 한도에 도달했습니다.", { "Retry-After": "86400" });
  if (prior?.duplicate) return jsonError(c, 409, "DUPLICATE_REPORT", "같은 내용이 이미 접수되었습니다.");
  const existing = await c.env.DB.prepare("SELECT case_number, access_token_hash FROM cases WHERE submission_request_id = ?").bind(report.submissionRequestId).first<{ case_number: string; access_token_hash: string }>();
  if (existing) return jsonError(c, 409, "REQUEST_ALREADY_USED", "이미 처리된 접수 요청입니다.");
  const caseNumber = makeCaseNumber(); const accessToken = randomBase64Url(32); const accessHash = await sha256(accessToken); const now = isoNow(); const analysis = await generateAnalysis(caseNumber);
  const insert = await c.env.DB.prepare(`INSERT INTO cases (case_number, access_token_hash, submission_request_id, submitter_hash, content_fingerprint, title, reproduction_steps, expected_result, actual_result, environment, severity, evidence_emoji, category, public_review_consent, consented_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?) RETURNING id`).bind(caseNumber, accessHash, report.submissionRequestId, c.get("visitorHash"), fingerprint, report.title, report.reproductionSteps, report.expectedResult, report.actualResult, report.environment, report.severity, report.evidenceEmoji, report.category, now, now, now).first<{ id: number }>();
  if (!insert) return jsonError(c, 500, "CREATE_FAILED", "사건 번호 발급에 실패했습니다.");
  await c.env.DB.batch([
    c.env.DB.prepare("INSERT INTO case_analyses (case_id, engine_version, department, initial_grade, workaround, expected_version, bureaucracy_waste_index, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").bind(insert.id, analysis.engineVersion, analysis.department, analysis.initialGrade, analysis.workaround, analysis.expectedVersion, analysis.bureaucracyWasteIndex, now),
    c.env.DB.prepare("INSERT INTO timeline_events (case_id, event_type, event_key, is_public, actor_type, created_at) VALUES (?, 'SUBMITTED', 'submitted', 1, 'system', ?)").bind(insert.id, now),
    c.env.DB.prepare("INSERT INTO timeline_events (case_id, event_type, event_key, is_public, actor_type, created_at) VALUES (?, 'PREANALYSIS_COMPLETED', 'preanalysis', 1, 'system', ?)").bind(insert.id, now),
  ]);
  return jsonData(c, { caseNumber, accessToken, statusUrl: `/submissions/${accessToken}`, analysis }, 201);
});

app.post("/api/v1/submissions/status", async c => {
  const limited = await requireLimits(c, "STATUS_GLOBAL", "STATUS_VISITOR"); if (limited) return limited;
  let raw: unknown; try { raw = await parseJson(c); } catch { return jsonError(c, 404, "NOT_FOUND", "사건 기록을 찾지 못했습니다."); }
  const parsed = statusRequestSchema.safeParse(raw); if (!parsed.success) return jsonError(c, 404, "NOT_FOUND", "사건 기록을 찾지 못했습니다.");
  const row = await c.env.DB.prepare(`SELECT c.*, a.department, a.initial_grade, a.workaround, a.expected_version, a.bureaucracy_waste_index FROM cases c JOIN case_analyses a ON a.case_id = c.id WHERE c.access_token_hash = ?`).bind(await sha256(parsed.data.accessToken)).first<Record<string, unknown>>();
  if (!row) return jsonError(c, 404, "NOT_FOUND", "사건 기록을 찾지 못했습니다."); c.header("Cache-Control", "no-store"); c.header("X-Robots-Tag", "noindex, nofollow"); c.header("Referrer-Policy", "no-referrer");
  return jsonData(c, mapCase(row, []));
});

app.get("/api/v1/home", async c => { const limited = await requireLimits(c, "READ_GLOBAL", "READ_VISITOR"); if (limited) return limited; const bugs = await c.env.DB.prepare("SELECT case_number, title, lifecycle_status, resolution_code, reproduction_count, published_at FROM cases WHERE visibility_status = 'public' ORDER BY published_at DESC, id DESC LIMIT 5").all(); const patch = await c.env.DB.prepare("SELECT id, slug, title, introduction, published_at FROM patch_notes WHERE status = 'published' ORDER BY published_at DESC, id DESC LIMIT 1").first(); return jsonData(c, { bugs: bugs.results.map(mapSummary), patchNote: patch ? mapPatch(patch) : null }); });
app.get("/api/v1/bugs", async c => { const limited = await requireLimits(c, "READ_GLOBAL", "READ_VISITOR"); if (limited) return limited; const limit = Math.min(Math.max(Number(c.req.query("limit") ?? 20), 1), 50); const lifecycle = c.req.query("lifecycle"); const resolution = c.req.query("resolution"); let sql = "SELECT case_number, title, lifecycle_status, resolution_code, reproduction_count, published_at FROM cases WHERE visibility_status = 'public'"; const binds: unknown[] = []; if (lifecycle) { sql += " AND lifecycle_status = ?"; binds.push(lifecycle); } if (resolution) { sql += " AND resolution_code = ?"; binds.push(resolution); } sql += " ORDER BY published_at DESC, id DESC LIMIT ?"; binds.push(limit); const result = await c.env.DB.prepare(sql).bind(...binds).all(); return jsonData(c, { items: result.results.map(mapSummary), nextCursor: null }); });
app.get("/api/v1/bugs/:caseNumber", async c => { const limited = await requireLimits(c, "READ_GLOBAL", "READ_VISITOR"); if (limited) return limited; const row = await c.env.DB.prepare(`SELECT c.*, a.department, a.initial_grade, a.workaround, a.expected_version, a.bureaucracy_waste_index FROM cases c JOIN case_analyses a ON a.case_id = c.id WHERE c.case_number = ? AND c.visibility_status = 'public'`).bind(c.req.param("caseNumber")).first<Record<string, unknown>>(); if (!row) return jsonError(c, 404, "NOT_FOUND", "사건 기록을 찾지 못했습니다."); const events = await c.env.DB.prepare("SELECT event_type, metadata_json, created_at FROM timeline_events WHERE case_id = ? AND is_public = 1 ORDER BY created_at, id").bind(row.id).all(); return jsonData(c, mapCase(row, events.results)); });
app.post("/api/v1/bugs/:caseNumber/reproductions", async c => {
  if (c.env.PUBLIC_WRITE_MODE !== "enabled") return jsonError(c, 503, "WRITES_DISABLED", "현재 재현 접수 업무가 일시 중단되었습니다."); if (!requireOrigin(c)) return jsonError(c, 403, "ORIGIN_REJECTED", "요청 출처를 확인할 수 없습니다.");
  const limited = await requireLimits(c, "REPRO_GLOBAL", "REPRO_VISITOR"); if (limited) return limited; let raw: unknown; try { raw = await parseJson(c); } catch { return jsonError(c, 400, "INVALID_BODY", "요청 형식이 올바르지 않습니다."); }
  const parsed = reproductionSchema.safeParse(raw); if (!parsed.success) return jsonError(c, 400, "INVALID_BODY", "요청 형식이 올바르지 않습니다."); const caseNumber = c.req.param("caseNumber");
  if (!await verifyContext(c.env, parsed.data.botContext, "reproduce", c.get("visitorHash"), caseNumber)) return jsonError(c, 400, "REQUEST_REJECTED", "요청을 확인할 수 없습니다.");
  if (!await verifyTurnstile(c.env, parsed.data.turnstileToken, "reproduce", crypto.randomUUID())) return jsonError(c, 403, "BOT_VERIFICATION_FAILED", "사람 확인에 실패했습니다.");
  const target = await c.env.DB.prepare("SELECT id, reproduction_count FROM cases WHERE case_number = ? AND visibility_status = 'public'").bind(caseNumber).first<{ id: number; reproduction_count: number }>(); if (!target) return jsonError(c, 404, "NOT_FOUND", "사건 기록을 찾지 못했습니다.");
  const existing = await c.env.DB.prepare("SELECT 1 AS yes FROM reproduction_reports WHERE case_id = ? AND visitor_hash = ?").bind(target.id, c.get("visitorHash")).first(); if (existing) return jsonData(c, { reproductionCount: target.reproduction_count, alreadyReported: true, message: reproductionBand(target.reproduction_count) });
  const hourAgo = new Date(Date.now() - 3_600_000).toISOString(); const recent = await c.env.DB.prepare("SELECT COUNT(*) AS count FROM reproduction_reports WHERE visitor_hash = ? AND created_at >= ?").bind(c.get("visitorHash"), hourAgo).first<{ count: number }>(); if ((recent?.count ?? 0) >= 20) return jsonError(c, 429, "HOURLY_REPRODUCTION_LIMIT", "시간당 재현 접수 한도에 도달했습니다.", { "Retry-After": "3600" });
  const now = isoNow(); const inserted = await c.env.DB.prepare("INSERT INTO reproduction_reports (case_id, visitor_hash, created_at) VALUES (?, ?, ?) ON CONFLICT(case_id, visitor_hash) DO NOTHING RETURNING id").bind(target.id, c.get("visitorHash"), now).first(); if (!inserted) return jsonData(c, { reproductionCount: target.reproduction_count, alreadyReported: true, message: reproductionBand(target.reproduction_count) });
  const updated = await c.env.DB.prepare("UPDATE cases SET reproduction_count = reproduction_count + 1, updated_at = ? WHERE id = ? RETURNING reproduction_count").bind(now, target.id).first<{ reproduction_count: number }>(); const count = updated?.reproduction_count ?? target.reproduction_count + 1; const threshold = crossedThreshold(count);
  if (threshold) await c.env.DB.prepare("INSERT OR IGNORE INTO timeline_events (case_id, event_type, event_key, is_public, actor_type, metadata_json, created_at) VALUES (?, 'REPRODUCTION_THRESHOLD_REACHED', ?, 1, 'system', ?, ?)").bind(target.id, `repro-${threshold}`, safeMetadata({ threshold }), now).run();
  return jsonData(c, { reproductionCount: count, alreadyReported: false, message: reproductionBand(count) }, 201);
});

app.get("/api/v1/patch-notes", async c => { const limited = await requireLimits(c, "READ_GLOBAL", "READ_VISITOR"); if (limited) return limited; const rows = await c.env.DB.prepare("SELECT p.id, p.slug, p.title, p.introduction, p.published_at, COUNT(i.id) AS item_count FROM patch_notes p LEFT JOIN patch_note_items i ON i.patch_note_id = p.id WHERE p.status = 'published' GROUP BY p.id ORDER BY p.published_at DESC, p.id DESC LIMIT 20").all(); return jsonData(c, { items: rows.results.map(mapPatch) }); });
app.get("/api/v1/patch-notes/:slug", async c => { const limited = await requireLimits(c, "READ_GLOBAL", "READ_VISITOR"); if (limited) return limited; const note = await c.env.DB.prepare("SELECT * FROM patch_notes WHERE slug = ? AND status = 'published'").bind(c.req.param("slug")).first<Record<string, unknown>>(); if (!note) return jsonError(c, 404, "NOT_FOUND", "패치노트를 찾지 못했습니다."); const rows = await c.env.DB.prepare("SELECT i.section_code, i.title_snapshot, i.editorial_note, c.case_number FROM patch_note_items i JOIN cases c ON c.id = i.case_id WHERE i.patch_note_id = ? AND c.visibility_status = 'public' ORDER BY i.section_code, i.display_order").bind(note.id).all(); const sections = patchSectionCodes.map(code => ({ code, label: resolutionLabels[code], items: rows.results.filter(x => x.section_code === code).map(x => ({ caseNumber: x.case_number, title: x.title_snapshot, editorialNote: x.editorial_note })) })).filter(x => x.items.length); return jsonData(c, { ...mapPatch(note), sections }); });

app.get("/og/bugs/:caseNumber.jpg", async c => serveOg(c, "case", c.req.param("caseNumber") ?? ""));
app.get("/og/patch-notes/:slug.jpg", async c => serveOg(c, "patch", c.req.param("slug") ?? ""));

async function serveOg(c: AppContext, type: "case" | "patch", key: string) {
  const sql = type === "case" ? "SELECT o.data FROM og_assets o JOIN cases c ON c.id = o.case_id WHERE c.case_number = ? AND c.visibility_status = 'public'" : "SELECT o.data FROM og_assets o JOIN patch_notes p ON p.id = o.patch_note_id WHERE p.slug = ? AND p.status = 'published'";
  const row = await c.env.DB.prepare(sql).bind(key).first<{ data: ArrayBuffer }>(); if (!row) return new Response("Not found", { status: 404 }); return new Response(row.data, { headers: { "Content-Type": "image/jpeg", "Cache-Control": "no-store" } });
}

function mapSummary(row: Record<string, unknown>) { return { caseNumber: row.case_number, title: row.title, lifecycleStatus: row.lifecycle_status, resolutionCode: row.resolution_code, reproductionCount: row.reproduction_count, publishedAt: row.published_at }; }
function mapPatch(row: Record<string, unknown>) { return { id: row.id, slug: row.slug, title: row.title, introduction: row.introduction, publishedAt: row.published_at, itemCount: row.item_count }; }
function mapCase(row: Record<string, unknown>, events: Record<string, unknown>[]) { return { ...mapSummary(row), reproductionSteps: row.reproduction_steps, expectedResult: row.expected_result, actualResult: row.actual_result, environment: row.environment, severity: row.severity, category: row.category, evidenceEmoji: row.evidence_emoji, officialComment: row.official_comment, moderationStatus: row.moderation_status, visibilityStatus: row.visibility_status, moderationNote: row.moderation_note, analysis: { department: row.department, initialGrade: row.initial_grade, workaround: row.workaround, expectedVersion: row.expected_version, bureaucracyWasteIndex: row.bureaucracy_waste_index }, timeline: events.map(x => ({ eventType: x.event_type, createdAt: x.created_at, metadata: JSON.parse(String(x.metadata_json ?? "{}")) })) }; }

app.notFound(c => jsonError(c, 404, "NOT_FOUND", "요청한 기록을 찾지 못했습니다."));
app.onError((error, c) => { console.error(JSON.stringify({ requestId: c.get("requestId"), route: c.req.routePath, error: error.name })); return jsonError(c, 500, "INTERNAL_ERROR", "관제 처리 중 오류가 발생했습니다."); });

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/og/")) return app.fetch(request, env, ctx);
    if (/^\/bugs\/[^/]+$/.test(url.pathname) || /^\/patch-notes\/[^/]+$/.test(url.pathname) || url.pathname.startsWith("/submissions/")) {
      const asset = await env.ASSETS.fetch(new Request(new URL("/index.html", request.url), request));
      if (!asset.ok) return asset;
      let html = await asset.text(); const isPrivate = url.pathname.startsWith("/submissions/");
      if (isPrivate) html = html.replace("</head>", '<meta name="robots" content="noindex,nofollow"><meta name="referrer" content="no-referrer"></head>');
      else {
        const bug = url.pathname.match(/^\/bugs\/([^/]+)$/);
        const patch = url.pathname.match(/^\/patch-notes\/([^/]+)$/);
        let meta: { title: string; description: string; imagePath: string } | null = null;
        if (bug) {
          const row = await env.DB.prepare("SELECT title,lifecycle_status,resolution_code,reproduction_count FROM cases WHERE case_number=? AND visibility_status='public'").bind(decodeURIComponent(bug[1] ?? "")).first<Record<string, unknown>>();
          if (row) meta = { title: `${row.title} · 인류 버그 센터`, description: `${row.reproduction_count}명이 동일 현상을 재현했습니다. ${reproductionBand(Number(row.reproduction_count))}`, imagePath: `/og/bugs/${encodeURIComponent(bug[1] ?? "")}.jpg` };
        } else if (patch) {
          const row = await env.DB.prepare("SELECT title,introduction FROM patch_notes WHERE slug=? AND status='published'").bind(decodeURIComponent(patch[1] ?? "")).first<Record<string, unknown>>();
          if (row) meta = { title: `${row.title} · 인류 OS 패치노트`, description: String(row.introduction), imagePath: `/og/patch-notes/${encodeURIComponent(patch[1] ?? "")}.jpg` };
        }
        if (!meta) return new Response("기록을 찾지 못했습니다.", { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8", "X-Robots-Tag": "noindex" } });
        html = injectSocialMeta(html, meta, url.origin + url.pathname, url.origin + meta.imagePath);
      }
      const response = new Response(html, asset); response.headers.set("Content-Type", "text/html; charset=utf-8"); response.headers.set("Cache-Control", "no-store"); if (isPrivate) { response.headers.set("X-Robots-Tag", "noindex, nofollow"); response.headers.set("Referrer-Policy", "no-referrer"); } return response;
    }
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;

function escapeMeta(value: string) { return value.replaceAll("&", "&amp;").replaceAll('"', "&quot;").replaceAll("<", "&lt;").replaceAll(">", "&gt;"); }
function injectSocialMeta(html: string, meta: { title: string; description: string }, canonical: string, image: string) {
  const title = escapeMeta(meta.title); const description = escapeMeta(meta.description); const url = escapeMeta(canonical); const imageUrl = escapeMeta(image);
  html = html.replace(/<title>.*?<\/title>/s, `<title>${title}</title>`).replace(/<meta name="description"[^>]*>/, `<meta name="description" content="${description}">`);
  return html.replace("</head>", `<link rel="canonical" href="${url}"><meta property="og:type" content="article"><meta property="og:title" content="${title}"><meta property="og:description" content="${description}"><meta property="og:url" content="${url}"><meta property="og:image" content="${imageUrl}"><meta property="og:image:width" content="1200"><meta property="og:image:height" content="630"><meta name="twitter:card" content="summary_large_image"></head>`);
}

export const botContextTest = {
  sign: (secret: string, payload: BotPayload) => signContext({ BOT_CONTEXT_SECRET: secret } as Env, payload),
  verify: (secret: string, token: string, purpose: BotPurpose, visitorHash: string, caseNumber?: string) => verifyContext({ BOT_CONTEXT_SECRET: secret } as Env, token, purpose, visitorHash, caseNumber),
};
