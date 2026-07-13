# 인류 버그 센터

> 인류는 아직 베타 버전입니다.

익명 사용자가 일상의 인류 이상 현상을 신고하고, 다른 사용자가 재현 여부를 보고하며, 운영자가 공식 판정과 인류 OS 패치노트를 발행하는 Cloudflare Workers 웹앱입니다.

## 구조

- `apps/public`: 공개 React 앱과 Hono Worker
- `apps/admin`: Cloudflare Access로 보호할 운영자 React 앱과 Hono Worker
- `packages/shared`: Zod 계약, 상태·문구·사전 분석
- `migrations`: 두 Worker가 공유하는 D1 SQL migration

## 로컬 실행

1. 각 앱의 `.dev.vars.example`을 `.dev.vars`로 복사하고 로컬 secret을 설정합니다.
2. `npm run db:migrate:local`
3. `npm run dev`
4. Public은 `http://localhost:5173`, Admin은 `http://localhost:5174`에서 엽니다.

로컬 환경에서는 Cloudflare Rate Limiting binding을 우회하지만, 나머지 검증 순서는 유지합니다. Turnstile은 공식 테스트 key를 사용합니다.

## 배포 전 필수 설정

- 두 `wrangler.jsonc`의 D1 `database_id`를 실제 ID로 교체
- production에서 `ENVIRONMENT=production`과 정확한 Public/Admin origin 설정
- Turnstile widget 2개와 sitekey/secret 등록
- Public Worker secrets: `VISITOR_HASH_SECRET`, `BOT_CONTEXT_SECRET`, `TURNSTILE_REPORT_SECRET`, `TURNSTILE_REPRODUCE_SECRET`
- Admin Worker secrets: `ADMIN_AUDIT_HASH_SECRET`
- Admin Worker `TEAM_DOMAIN`, `POLICY_AUD` 설정 후 workers.dev 주소에 Access 활성화
- production 배포 전 `wrangler d1 migrations apply human-bug-center-db --remote`

`PUBLIC_WRITE_MODE=disabled`로 배포하면 공개 읽기는 유지하면서 신고와 재현 쓰기만 즉시 중단할 수 있습니다.
