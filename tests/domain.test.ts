import { afterEach, describe, expect, it, vi } from "vitest";
import { generateAnalysis, reportSchema, reproductionBand, crossedThreshold } from "../packages/shared/src/index";
import { botContextTest } from "../apps/public/worker/index";

afterEach(() => vi.useRealTimers());

describe("규칙 기반 사전 분석", () => {
  it("같은 사건 번호에 항상 같은 결과를 만든다", async () => {
    const first = await generateAnalysis("HBC-260713-ABC123");
    const second = await generateAnalysis("HBC-260713-ABC123");
    expect(second).toEqual(first);
    expect(first.engineVersion).toBe("v1");
  });
  it("행정력 낭비 지수를 범위 안에 둔다", async () => {
    const result = await generateAnalysis("HBC-260713-ZZZ999");
    expect(result.bureaucracyWasteIndex).toBeGreaterThanOrEqual(0);
    expect(result.bureaucracyWasteIndex).toBeLessThanOrEqual(100);
  });
});

describe("재현 문구", () => {
  it.each([[0,"단독"],[1,"소규모"],[5,"반복"],[20,"광범위"],[50,"기본 사양"]])("%i명 구간", (count, phrase) => {
    expect(reproductionBand(count)).toContain(phrase);
  });
  it("정해진 수에서만 임계 이벤트를 반환한다", () => {
    expect([1,5,20,50].map(crossedThreshold)).toEqual([1,5,20,50]);
    expect(crossedThreshold(6)).toBeNull();
  });
});

describe("신고 계약", () => {
  const valid = {
    submissionRequestId: "7c9d3f04-8e3b-43d9-bbe3-41eff67cc404",
    title: "누우면 실수가 재생됨",
    reproductionSteps: "침대에 누워 눈을 감는다.",
    expectedResult: "잠이 든다.",
    actualResult: "과거 실수가 재생된다.",
    publicReviewConsent: true,
    botContext: "a".repeat(40),
    turnstileToken: "test",
  };
  it("공개 동의 없는 신고를 거절한다", () => {
    expect(reportSchema.safeParse({ ...valid, publicReviewConsent: false }).success).toBe(false);
  });
  it("허니팟이 채워진 신고를 거절한다", () => {
    expect(reportSchema.safeParse({ ...valid, website: "spam.example" }).success).toBe(false);
  });
});

describe("서명형 봇 컨텍스트", () => {
  const secret = "test-secret-that-is-long-enough-for-hmac";
  const visitorHash = "0123456789abcdef01234567-extra";
  const issuedAt = Date.parse("2026-07-13T08:00:00.000Z");
  async function token(purpose: "report" | "reproduce" = "report", caseNumber?: string) {
    return botContextTest.sign(secret, { v: 1, p: purpose, vh: visitorHash.slice(0, 24), cn: caseNumber, iat: issuedAt, exp: issuedAt + 30 * 60_000, n: "fixed-nonce" });
  }
  it("최소 대기시간 뒤 올바른 신고 컨텍스트를 허용한다", async () => {
    vi.useFakeTimers(); vi.setSystemTime(issuedAt + 3_001);
    expect(await botContextTest.verify(secret, await token(), "report", visitorHash)).toBe(true);
  });
  it("너무 빠른 신고와 만료된 컨텍스트를 거절한다", async () => {
    vi.useFakeTimers(); const signed = await token(); vi.setSystemTime(issuedAt + 2_999);
    expect(await botContextTest.verify(secret, signed, "report", visitorHash)).toBe(false);
    vi.setSystemTime(issuedAt + 30 * 60_000 + 1);
    expect(await botContextTest.verify(secret, signed, "report", visitorHash)).toBe(false);
  });
  it("서명 위조와 다른 목적·방문자 재사용을 거절한다", async () => {
    vi.useFakeTimers(); vi.setSystemTime(issuedAt + 3_001); const signed = await token();
    expect(await botContextTest.verify(secret, `${signed.slice(0, -1)}x`, "report", visitorHash)).toBe(false);
    expect(await botContextTest.verify(secret, signed, "reproduce", visitorHash)).toBe(false);
    expect(await botContextTest.verify(secret, signed, "report", `different-${visitorHash}`)).toBe(false);
  });
  it("재현 컨텍스트를 사건 번호에 결합한다", async () => {
    vi.useFakeTimers(); vi.setSystemTime(issuedAt + 751); const signed = await token("reproduce", "HBC-260713-ABC123");
    expect(await botContextTest.verify(secret, signed, "reproduce", visitorHash, "HBC-260713-ABC123")).toBe(true);
    expect(await botContextTest.verify(secret, signed, "reproduce", visitorHash, "HBC-260713-OTHER1")).toBe(false);
  });
});
