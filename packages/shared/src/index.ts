import { z } from "zod";

export const visibilityStatuses = ["pending", "public", "hidden"] as const;
export const moderationStatuses = ["pending", "approved", "rejected"] as const;
export const lifecycleStatuses = ["open", "reviewing", "closed"] as const;
export const resolutionCodes = [
  "PATCHED", "KNOWN_ISSUE", "WORKS_AS_DESIGNED", "WONT_FIX",
  "CANNOT_REPRODUCE", "USER_ERROR", "ESCALATED_TO_UNIVERSE", "DUPLICATE",
] as const;
export const patchSectionCodes = [
  "PATCHED", "KNOWN_ISSUE", "WORKS_AS_DESIGNED", "WONT_FIX",
  "CANNOT_REPRODUCE", "ESCALATED_TO_UNIVERSE",
] as const;

export type VisibilityStatus = typeof visibilityStatuses[number];
export type ModerationStatus = typeof moderationStatuses[number];
export type LifecycleStatus = typeof lifecycleStatuses[number];
export type ResolutionCode = typeof resolutionCodes[number];

export const categoryCodes = ["communication", "habit", "work", "relationship", "body_mind", "society", "other"] as const;
export const severityCodes = ["minor", "annoying", "serious", "critical"] as const;

export const reportSchema = z.object({
  submissionRequestId: z.uuid(),
  title: z.string().trim().min(3).max(80),
  reproductionSteps: z.string().trim().min(5).max(1000),
  expectedResult: z.string().trim().min(2).max(500),
  actualResult: z.string().trim().min(2).max(500),
  environment: z.string().trim().max(120).optional().default(""),
  severity: z.enum(severityCodes).nullable().optional().default(null),
  evidenceEmoji: z.enum(["🫠", "🤦", "🙃", "😵‍💫", "🫥", "🤔"]).nullable().optional().default(null),
  category: z.enum(categoryCodes).nullable().optional().default(null),
  publicReviewConsent: z.literal(true),
  botContext: z.string().min(20).max(1500),
  turnstileToken: z.string().min(1).max(2048),
  website: z.string().max(0).optional().default(""),
});

export const botContextRequestSchema = z.object({
  purpose: z.enum(["report", "reproduce"]),
  caseNumber: z.string().regex(/^HBC-\d{6}-[A-Z0-9]{6}$/).optional(),
}).superRefine((value, ctx) => {
  if (value.purpose === "reproduce" && !value.caseNumber) ctx.addIssue({ code: "custom", message: "사건 번호가 필요합니다." });
});

export const statusRequestSchema = z.object({ accessToken: z.string().min(40).max(64) });
export const reproductionSchema = z.object({
  botContext: z.string().min(20).max(1500),
  turnstileToken: z.string().min(1).max(2048),
});

export const moderationSchema = z.object({
  action: z.enum(["approve", "reject", "hide", "restore", "reset"]),
  reason: z.string().trim().max(500).optional(),
});
export const lifecycleSchema = z.object({ lifecycleStatus: z.enum(["open", "reviewing"]) });
export const resolutionSchema = z.object({
  resolutionCode: z.enum(resolutionCodes),
  officialComment: z.string().trim().min(10).max(1000),
  duplicateOfCaseNumber: z.string().regex(/^HBC-\d{6}-[A-Z0-9]{6}$/).nullable().optional(),
});

export const patchDraftSchema = z.object({
  title: z.string().trim().min(3).max(100),
  slug: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/).max(80),
  introduction: z.string().trim().max(1000),
});
export const patchItemsSchema = z.object({
  items: z.array(z.object({
    caseNumber: z.string(),
    sectionCode: z.enum(patchSectionCodes),
    editorialNote: z.string().trim().max(500).default(""),
    displayOrder: z.number().int().min(0).max(999),
  })).max(100),
});

export const resolutionLabels: Record<ResolutionCode, string> = {
  PATCHED: "수정된 버그", KNOWN_ISSUE: "관측 중인 문제", WORKS_AS_DESIGNED: "인류 기본 사양",
  WONT_FIX: "수정 계획 없음", CANNOT_REPRODUCE: "재현 불가", USER_ERROR: "사용자 오류",
  ESCALATED_TO_UNIVERSE: "상위 은하 관제실 이관", DUPLICATE: "중복 사건",
};

export function reproductionBand(count: number) {
  if (count === 0) return "단독 사용자 환경에서만 발생한 것으로 추정됩니다.";
  if (count < 5) return "소규모 재현 보고가 접수되었습니다.";
  if (count < 20) return "반복 가능한 인류 결함으로 의심됩니다.";
  if (count < 50) return "광범위한 사용자 영향이 확인되었습니다.";
  return "문제가 아니라 인류 기본 사양일 가능성이 있습니다.";
}

const departments = ["일상 오작동 접수과", "사회적 신호 해석실", "기억 누락 대응반", "미루기 관제과", "말실수 복구팀", "집중력 누수 조사국", "관계 프로토콜 담당실", "수면 부족 통제반", "선택 장애 조정실", "인류 습관 감사과", "기분 변동 관측소", "우주 민원 이관과"];
const workarounds = ["일단 물을 한 잔 마신 뒤 다시 시도하십시오.", "관련 인간과 10분간 거리를 두십시오.", "내일의 본인에게 임시 이관하십시오.", "정상 작동인 척하고 로그를 추가 수집하십시오.", "같은 문장을 더 천천히 반복하십시오.", "현재 탭을 닫고 산책 절차를 실행하십시오.", "기대치를 12% 낮춘 뒤 재시도하십시오.", "간식 패치를 적용하고 상태를 관찰하십시오.", "말하기 전 내부 검토를 한 차례 수행하십시오.", "잠시 아무 결정도 하지 않는 우회로를 권장합니다.", "주변 인간 한 명에게 재현 여부를 문의하십시오.", "문제를 메모한 뒤 기억 장치에서 내려놓으십시오."];
const versions = ["인류 OS 1.0 미정", "다음 생애 후보", "문명 2.1 이후", "은하 표준안 승인 후", "주말 안정화 빌드", "충분한 수면 릴리스", "사회 합의 패치 0.9", "다음 월요일 베타", "담당자 성장 이후", "예정 없음(관찰만 수행)"];

function readU32(bytes: Uint8Array, offset: number) {
  return ((bytes[offset] ?? 0) * 0x1000000 + (bytes[offset + 1] ?? 0) * 0x10000 + (bytes[offset + 2] ?? 0) * 0x100 + (bytes[offset + 3] ?? 0)) >>> 0;
}
export async function generateAnalysis(caseNumber: string) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`hbc-analysis:v1:${caseNumber}`)));
  return {
    engineVersion: "v1",
    department: departments[readU32(digest, 0) % departments.length]!,
    initialGrade: `D-${(readU32(digest, 4) % 5) + 1}`,
    workaround: workarounds[readU32(digest, 8) % workarounds.length]!,
    expectedVersion: versions[readU32(digest, 12) % versions.length]!,
    bureaucracyWasteIndex: readU32(digest, 16) % 101,
  };
}

export const thresholds = [1, 5, 20, 50] as const;
export function crossedThreshold(count: number) { return thresholds.includes(count as 1 | 5 | 20 | 50) ? count : null; }
