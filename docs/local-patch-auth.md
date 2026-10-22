# patch-auth 로컬 통합 검증

이 작업은 로그인과 데이터 API를 분리한다. 클라이언트는 patch-auth의 PocketBase auth collection에 직접 로그인한다. Exposure는 인스턴스마다 하나의 고정 origin만 사용한다. 데이터용 인스턴스와 Grant 관리용 인스턴스를 나누며, 로그인용 Exposure 인스턴스나 토큰에서 선택하는 issuer 라우팅은 없다.

권한 집행은 Exposure에서만 수행한다. 관리용 Exposure는 비공개 Grant voter에 직접 판정을 요청하고, 데이터용 Exposure만 patch-data에 인접한 learner에 판정을 요청한다. patch-data는 순정 PocketBase이며 learner를 호출하지 않고 기존 사업 API 요청만 처리한다. API 앞의 내부 권한 검사 노드와 관리용 Rhiza 복제본은 없다. 사용자 bearer는 Grant 판정에만 사용하고 데이터 API에는 기존 서버 소유 서비스 토큰만 전달한다.

데이터 단위는 **순정 PocketBase + Exposure sidecar + Grant 읽기 복제본**이고, 관리 단위는 **Grant + Exposure sidecar**다. 다른 PocketBase나 다른 시스템에도 같은 Exposure를 사용하며 backend 차이는 capability catalog, 고정 upstream origin, 기존 upstream 인증 설정으로 표현한다. 별도 backend 어댑터나 권한 검사 코드는 추가하지 않는다.

## 작업 체크아웃

- patch-auth: `/Users/cypark/Documents/work/patch-auth`
- patch-data: `/Users/cypark/Documents/work/patch-data-auth-extraction`
- Grant: `/Users/cypark/Documents/work/grant-porting-go`
- Exposure: `/Users/cypark/Documents/work/exposure-patch-auth-local`, `feature/patch-auth-local`

원래 `/Users/cypark/Documents/work/exposure`의 미커밋 작업은 이 검증에 사용하지 않는다. 검증용 서버와 데이터 디렉터리는 모두 별도로 생성하며 외부 배포·레지스트리 업로드는 수행하지 않는다.

## Exposure 인증 계약

기존 Rauthy 모드는 기본값으로 유지한다. PocketBase 토큰을 사용하는 고정 upstream에는 다음 설정을 추가한다.

| 환경 변수 | 의미 |
|---|---|
| `EXPOSURE_CREDENTIAL_MODE=pocketbase` | 토큰 claim 형태를 배포 설정으로 선택 |
| `EXPOSURE_POCKETBASE_ISSUER` | Grant와 동일한 canonical patch-auth origin; 경로·끝 slash·기본 port 표기 없음 |
| `EXPOSURE_POCKETBASE_COLLECTION_ID` | 고정 auth collection ID; collection 이름이 아님 |
| `EXPOSURE_POCKETBASE_APPLICATION_ID` | Grant가 검증 후 사용하는 application ID |
| `EXPOSURE_PROVIDER_AUTHORIZATION_MODE=service-token` | 사용자 토큰을 데이터 서버로 전달하지 않고 서버 전용 토큰을 사용 |
| `EXPOSURE_PROVIDER_TOKEN_FILE` | raw 데이터 서버 토큰을 담은 비공개 파일 |

JWT의 `id`, `collectionId`, `type=auth`는 검증된 신원이 아니라 요청 결합용 힌트다. issuer는 토큰의 `iss`에서 가져오지 않는다. Exposure는 `pocketbase:<설정 issuer>/<collectionId>/<id>`를 subject로, 설정 application ID를 audience로 전달한다. Grant는 실제 auth-refresh 결과로 신원을 확인하고 두 값을 비교한다. 잘못된 collection, 토큰 종류, 중복 claim, 서명 변조는 권한을 부여하지 않는다.

patch-data의 auth collection을 base collection으로 바꾸면 patch-auth가 발급한 사용자 토큰으로 데이터 서버에 직접 로그인할 수 없다. 따라서 이 로컬 검증은 별도의 합성 PocketBase `_superusers` 토큰을 Exposure 서버에 제공한다. catalog의 `request.authorization`도 `service-token`이어야 하며, 이 모드에서는 활성 `public_authn` capability를 거부한다. Grant가 허용한 정확한 리소스 요청에만 서버 토큰을 붙인다. 이 토큰은 catalog·Grant decision·클라이언트 응답에 포함하지 않는다. 이는 로컬 PEP의 높은 권한 경계이며 운영용 최소 권한 설계를 완료했다는 의미가 아니다.


Grant 관리용 인스턴스는 `forward-user`를 사용하고 조직 헤더와 JSON Content-Type만 명시적으로 전달한다. 사용자 관리 API는 Grant voter에서 원래의 관리 권한을 다시 검사한다. 최초 owner·provider·PEP·catalog 등록과 master-key 관리 API는 비공개 초기화 경로로 남는다. 관리용 catalog·판정·upstream 주소는 모두 비공개 Grant voter를 직접 가리켜 Exposure로 되돌아가는 재귀를 막는다.

응답 계약의 선택 필드 `errorStatuses`는 전달할 304와 400–599 상태를 오름차순으로 지정한다. 지정하지 않은 오류는 502로 처리한다. 등록한 응답도 크기 제한과 헤더 허용 목록을 거치며, redirect는 전달하지 않는다. 성공 상태와 204의 빈 본문을 보존하며, 명시적으로 허용한 Range·조건부 요청과 파일 응답 헤더도 전달한다.

## 기존 API와 Grant 매핑

API를 Exposure 전용 URL로 바꾸지 않는다. **Grant의 versioned capability catalog가** method·path·query·body 정책과 action/resource 추출 규칙을 정의하고, Exposure는 고정된 catalog digest를 확인하여 집행한다. 아래는 실제 로컬 fixture에 등록한 범위다.

| 기존 서비스 요청 | Grant action | resource 추출 |
|---|---|---|
| `GET /api/collections/plants/records/{id}` | `patch-data.plant.read` | `plant`, 경로의 `id` |
| `GET /api/v1/orgs/{organizationId}/groups` | `grant-management.manage` | `organization`, 경로의 `organizationId` |
| `POST /api/v1/orgs/{organizationId}/groups` | `grant-management.manage` | 동일; 기존 JSON body 전달 |
| `DELETE /api/v1/orgs/{organizationId}/groups/{groupId}` | `grant-management.manage` | 조직 ID를 선택하고 전체 경로를 판정에 결합 |

이는 모든 PocketBase API를 등록했다는 의미가 아니다. query는 `none` 또는 등록한 `exact` 정책을 사용한다. `text`는 UTF-8 바이트 수를 제한하고, 중복 값은 `repeated`로 선언한 항목만 허용한다. 판정에는 RFC3986 canonical query를 사용하고 upstream에는 원래 순서와 percent-escape 표기를 전달한다. `utf8Segment`로 선언한 파일명 경로만 안전한 percent encoding을 허용하며, 경로 구분자·이중 해석·dot segment는 거부한다.

본문은 `none`, `json`, `opaque`, `multipart`를 지원한다. opaque·multipart 본문은 크기와 Content-Type을 확인하고 임시 파일에 저장하여 전체 해시를 계산한 후 Grant 판정을 받는다. 허용 전에는 upstream으로 보내지 않으며, 전달할 때 multipart boundary를 포함한 Content-Type과 본문 바이트를 보존한다. 응답은 여전히 크기가 제한된 버퍼 방식이다. batch 권한 검사와 관계 expand는 구현되어 있다. SSE/realtime 구독 권한은 아직 지원하지 않는다.

목록은 `recordScope` 계약으로 Grant가 허용한 레코드 ID 범위를 받는다. Exposure는 전체 fexpr AST를 파싱하고 허용된 최상위 필드만 확인한 뒤, ID 조건과 사용자 필터를 AND로 결합한다. 별표 ID도 문자열 비교이며 전체 허용으로 바꾸지 않는다. 필터 외 query 원문은 보존하고, 페이지·페이지 크기·전체 개수 생략 옵션은 `pagination`의 명시적 역할과 `uint`·`bool` 형식으로만 허용한다. 정렬은 `sortParameter`에 연결된 허용 필드만 사용한다. 선언되지 않은 query 역할, 관계·함수·`@request`·`@collection` 접근은 거부한다. 허용 ID가 없으면 기존 API에 `1 = 0`을 전달하여 정상적인 빈 목록을 받는다. 따라서 필터링은 반환된 행을 잘라내는 방식이 아니며 native pagination과 전체 개수를 유지한다. ID 수·식 개수·필터 바이트 한도를 넘으면 요청을 거부하고, 범위를 잘라내거나 전체 허용으로 바꾸지 않는다.

등록한 요청에서는 기존 method와 path를 upstream에 전달하고, 응답 JSON bytes와 허용된 상태·헤더를 보존한다. backend에 필요한 변경이나 내부 권한 증거 프로토콜은 없다. 추가 API 공개는 Grant catalog의 명시적 범위와 지원되는 HTTP 계약 안에서 결정한다.

## 통합 테스트 실행

`internal/capability/pocketbase_e2e_test.go`와 `pocketbase_scope_e2e_test.go`는 실제 로컬 patch-auth·Grant·읽기 복제본·PocketBase를 사용한다. 후자는 공개 Grant API로 합성 파일 권한과 목록 범위 카탈로그를 등록한다. `pocketbase_catalog_e2e_test.go`는 실제 PocketBase 전송 규약을 검증하지만 PDP 응답은 통제된 테스트 서버를 사용하므로 Grant 권한 판정의 증거와 구분한다. 비밀값은 `umask 077`로 생성한 임시 JSON에 넣고, 파일 경로만 환경 변수로 전달한다. fixture에는 다음 필드가 필요하다.

```text
AuthOrigin, Collection, CollectionID, ApplicationID
AllowIdentity, AllowPassword, DenyIdentity, DenyPassword
GrantURL, GrantAppKey, ProviderID, PEPClientID, CatalogDigest
DataOrigin, ResourcePath, OrganizationID, DisabledLoginPath, UpstreamToken
```

fixture의 서버 origin은 HTTP loopback만 허용한다. 테스트 내부 Exposure는 `httptest`가 확보한 임의 포트를 사용한다. 별도 프로세스 실행에 필요한 Grant URL의 기존 8080 제한을 테스트 때문에 완화하지 않는다.

```sh
PATCH_AUTH_E2E_CONFIG=/absolute/path/to/private-fixture.json \
  go test ./internal/capability -run '^TestPocketBaseLocalEndToEnd$' -count=1 -v
```

기대 결과는 정상 비밀번호 로그인 성공, 잘못된 비밀번호 로그인 실패, 권한을 가진 사용자의 리소스 조회 200, 권한이 없는 사용자의 조회 403, 서명 변조·누락 토큰 401, patch-data의 폐기된 로그인 경로 404다. 테스트는 비밀번호·토큰·응답 본문을 출력하지 않는다. 일반 `go test ./...`에서는 fixture 설정이 없으면 이 실제 서버 검증만 건너뛴다.

PocketBase의 내부 관리자·운영 API 정책은 사용자 로그인 경로와 별개다. 데이터 서비스에서 관리용 경로가 남아 있다고 해서 사용자의 로그인 경로가 유지되는 것은 아니다. 실제 로컬 실행 후 확인한 관리자 경계와 재현 명령은 아래 실행 기록에 기록한다.

## 새 fixture로 재현하기

다음 한 명령이 PocketBase·Grant의 새 데이터와 키, 공개 API seed, Exposure 통합 테스트를 모두 재생성한다. 기존 `/tmp` 파일에 의존하지 않는다. 기본 port는 auth 18201, data 18202, Grant 18204이며, 이미 사용 중이면 시작하지 않는다. 종료 시 자신이 시작한 서버만 정리하고 검증 로그·비공개 fixture 파일은 출력한 임시 경로에 보존한다.

```sh
cd /Users/cypark/Documents/work/exposure-patch-auth-local
POCKETBASE_BIN=/tmp/grant-patch-auth-tools/pocketbase-0.40.3/pocketbase \
  sh scripts/verify-patch-auth-local.sh
```

바이너리는 실행 전에 PocketBase 0.40.3인지 확인한다. PATH의 `pocketbase`는 다른 버전일 수 있으므로 자동으로 선택하지 않는다. `KEEP_RUNNING=1`을 추가하면 성공 후 backend fixture 서버를 Ctrl-C까지 유지한다. Exposure 테스트 listener 자체는 매번 생성되고 닫힌다. 다른 checkout은 `PATCH_AUTH_DIR`, `PATCH_DATA_DIR`, `GRANT_DIR`로 지정할 수 있다. Grant 프로세스는 비운 환경에서 명시적 로컬 filesystem 설정으로 시작하므로 기존 remote runtime 설정을 상속하지 않는다.

## 복제본 구성과 검증 범위

기본 port 구성은 다음과 같다. Exposure listener 두 개는 Go 테스트가 비어 있는 loopback port에 생성하고 종료한다.

| 프로세스 | port | 역할 |
|---|---:|---|
| patch-auth | 18201 | 계정 인증 |
| 비공개 PocketBase | 18202 | 기존 사업 데이터 API |
| Grant voter | 18204 | 권한 쓰기와 관리 API |
| voter 비공개 runtime | 18205 | 고정 read-fence와 별도 운영 SQL 경계 |
| patch-data 인접 learner | 18206 | 데이터 PEP의 독립 권한 복제본 |
| voter QUIC | 18210/UDP | replica 동기화 |

데이터용 learner는 voter와 다른 데이터 디렉터리를 사용한다. voter 토큰이나 SQL 쓰기 키를 전달받지 않고, 공개 voter identity와 읽기 동기화 키 및 read-fence 키만 받는다. `scripts/replica-members`는 native Rhiza API로 공개 replica identity를 생성한다. learner는 권한 데이터를 자체 복제본에서 조회하되, 판정마다 voter의 선형화 fence를 확인하므로 연결이 끊긴 상태에서 stale 권한을 허용하지 않는다.

이 검증의 Rhiza 복제 대상은 **Grant 권한 데이터**다. PocketBase의 사업 데이터 SQLite를 Rhiza로 옮기지 않는다. 공개 API seed는 새 fixture 전용이며 기존 환경에 반복 적용하는 migration 도구가 아니다.

전체 검증은 실제 로그인, 데이터 응답과 비공개 PocketBase 응답의 동일성, 추가 권한 프로토콜 없는 데이터 API 접근, 두 번째 Exposure를 통한 관리 조회·생성·삭제, 422 및 204 보존, private bootstrap 미노출, 바인딩 회수 직후 거부를 확인한다. 기본 모드에서는 마지막에 voter를 중단하여 데이터용 learner가 준비 상태를 닫는지 확인하고, read-fence 키로 SQL을 실행할 수 없는지도 검사한다. `KEEP_RUNNING=1`에서는 서버를 유지하기 위해 voter 중단 검증을 생략한다. 이 모드의 관리 테스트는 fixture 바인딩을 회수하므로 데이터 허용 상태로 되돌리는 도구로 사용하지 않는다.

임시 디렉터리의 `start-grant.sh`, 각 로그, `e2e-config-path`를 통해 실행 구성을 확인할 수 있다. 비공개 JSON·키 내용을 출력하거나 공유하지 않는다. 종료는 wrapper를 실행한 터미널에서 Ctrl-C로 수행하며, 다른 프로세스를 이름 패턴으로 종료하지 않는다.

거부 사용자에게는 Grant 조직 멤버십이 없다. 조직·개인 권한 교집합 정책을 새로 구현한 것은 아니다. PocketBase의 `_superusers` 인증은 내부 관리용으로 남는다. 운영 배포·기존 사용자 계정 이전·기존 DB 자동 migration은 이 로컬 검증 범위에 포함되지 않는다.

2026-09-08 최종 구성으로 fresh wrapper가 통과했다(`patch-auth-e2e.OzwJSO`). 실제 PocketBase 0.40.3, 데이터용 Rhiza learner 하나, Exposure listener 두 개로 위 조건을 확인했다. Fiber나 별도 내부 권한 검사 프로세스는 실행하지 않았다. 종료 시 fixture 서버를 정리했다.
