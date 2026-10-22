# 내부 프로바이더 범위

Exposure는 현재 고정 오리진 catalog 기반 Grant+Exposure 내부 Kubernetes 프로바이더만 지원한다.

## 현재 내부 프로바이더

Exposure는 단일 고정 오리진으로 동작한다. catalog는 Grant versioned capability catalog이며, method·path·query·body 정책과 action/resource 추출 규칙을 정의한다. Exposure는 startup 시 catalog digest를 확인하고 요청마다 고정된 catalog에 따라 판정을 집행한다.

현재 내부 프로바이더는 다음 두 가지다.

- **patch-data**: 내부 PocketBase 사업 데이터 API.
- **grant-management**: Grant 관리 API.

오리진은 `validateProviderOrigin`에서 검증한다. HTTP loopback IP(`127.0.0.1`, `::1`) 또는 `.svc.cluster.local`로 끝나는 소문자 호스트이 허용된다. 연속 점(`..`)은 거부된다. HTTPS와 공인 호스트는 거부된다. Kubernetes 전체 서비스 이름 문법이나 포트를 검증하지 않으며, 설정된 고정 오리진은 운영자가 검토한다.

## Grant 관리 Exposure 라우트

grant-management Exposure 인스턴스는 정확히 3개 라우트를 노출한다.

1. `GET /api/v1/orgs/{organizationId}/groups`
2. `POST /api/v1/orgs/{organizationId}/groups`
3. `DELETE /api/v1/orgs/{organizationId}/groups/{groupId}`

세 라우트 모두 action `grant-management.manage`를 사용하며, resource는 조직 ID다.

provider·PEP·catalog 등록과 master-key 관리 API는 비공개 초기화 경로로 남으며 Exposure를 통해 노출되지 않는다. Exposure 관리 인스턴스는 `forward-user`를 사용하고 조직 헤더와 JSON Content-Type만 명시적으로 전달한다.

## 구현된 기능

**batch 권한 검사**: `batch.go`에 구현되어 있다. `pocketbase_batch_e2e_test.go`에서 JSON·multipart·PUT upsert가 검증되었다. 단일 root+children 판정, 거부 시 부분 쓰기 없음, 네이티브 atomic rollback이 동작한다.

**관계 expand**: `response_authorization.go`에 구현되어 있다. `pocketbase_expansion_e2e_test.go`에서 루트·관련·중첩·배열 독립 판정, 바이트 보존, 페이지 수 유지가 검증되었다.

**realtime/SSE 구독 권한**: 아직 구현되지 않았다.

## 로드맵 항목 (미구현)

다음 항목은 현재 로드맵에 포함되어 있지만 아직 구현되지 않았다.

**외부 플랫폼 Exposure**: mTLS 클라이언트 인증서·개인키는 Exposure가 보유하고, Provider TLS 종단자는 CA trust config와 허용된 identity를 보유한다. SDK 및 개발자 호스팅 Exposure는 로드맵 전용이다. 현재 mTLS 기능은 구현되어 있지 않다.

**외부 learner**: 유보 상태. 내부 learner만 현재 구현되어 있다.

**IdP 로그인 등록 vs Grant 권한**: 별개다. 향후 단일 워크플로우로 통합될 수 있지만 현재는 분리되어 있다.

## 관련 문서

- Grant 로드맵: https://github.com/mrchypark/grant/blob/main/docs/external-application-roadmap.md
- 등록 문서: https://github.com/mrchypark/grant/blob/main/docs/registration-api-management.md

위 문서는 Grant의 외부 애플리케이션 통합 로드맵과 등록 API 관리 문서이며, 현재 이 PR의 병행 PR 의존성으로 아직 배포되지 않았다.
