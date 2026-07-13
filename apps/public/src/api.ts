export type ApiEnvelope<T> = { data: T | null; error: { code: string; message: string } | null; requestId: string };
export async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, { credentials: "same-origin", ...options, headers: { "Content-Type": "application/json", ...(options?.headers ?? {}) } });
  const payload = await response.json() as ApiEnvelope<T>;
  if (!response.ok || payload.error) throw new Error(payload.error?.message ?? "요청을 처리하지 못했습니다.");
  return payload.data as T;
}

export type PublicConfig = { turnstileReportSiteKey: string; turnstileReproduceSiteKey: string };
let configPromise: Promise<PublicConfig> | undefined;
export function getPublicConfig() {
  configPromise ??= api<PublicConfig>("/api/v1/config");
  return configPromise;
}

declare global { interface Window { turnstile?: { render: (element: HTMLElement, options: Record<string, unknown>) => string; execute: (id: string) => void; reset: (id: string) => void } } }
let scriptPromise: Promise<void> | undefined;
export function loadTurnstile() {
  if (window.turnstile) return Promise.resolve();
  if (!scriptPromise) scriptPromise = new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true; script.defer = true; script.onload = () => resolve(); script.onerror = () => reject(new Error("사람 확인 모듈을 불러오지 못했습니다."));
    document.head.appendChild(script);
  });
  return scriptPromise;
}
export async function getTurnstileToken(container: HTMLElement, sitekey: string, action: string) {
  await loadTurnstile();
  return new Promise<string>((resolve, reject) => {
    let widgetId = "";
    widgetId = window.turnstile!.render(container, {
      sitekey, action, execution: "execute", appearance: "interaction-only", theme: "light",
      callback: (token: string) => { resolve(token); setTimeout(() => window.turnstile?.reset(widgetId), 0); },
      "error-callback": () => reject(new Error("사람 확인에 실패했습니다.")),
      "expired-callback": () => reject(new Error("사람 확인 시간이 만료되었습니다.")),
    });
    window.turnstile!.execute(widgetId);
  });
}
