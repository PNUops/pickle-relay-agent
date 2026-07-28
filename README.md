# pickle-relay-agent

Pickle(피클)은 부산대학교 구성원을 위한 셀프서비스 클라우드 플랫폼 **PNU Cloud**(정식 명칭: 부산대학교 클라우드 플랫폼)의 코드네임이다. 사용자가 웹 콘솔에서
VM을 신청하면 관리자 승인 후 Proxmox VE에 자동 프로비저닝되며, SSH 접속과 도메인 기반
HTTP(S) 공개까지 제공한다. 이 저장소는 그중 **포트포워딩 릴레이의 nftables 제어 에이전트**를 담당한다.

## 역할

플랫폼이 정의한 "원하는 매핑 집합"(공인 포트 → VM 포트 DNAT)을 받아, 릴레이 호스트의
nftables를 그 상태로 수렴시키는 작은 Go 데몬이다.

```
플랫폼 API ── 매핑 스냅샷(JSON, generation 태그) ──▶ relay-agent ──▶ nftables (netlink)
```

핵심 규약:

- **자기 테이블만 소유** — 에이전트는 `ip pickle_relay_dnat` 테이블 하나만 만들고 교체한다.
  룰셋 전체 flush는 코드에 존재하지 않는다(정적 배관 테이블은 호스트 부팅 설정 소유).
- **원자 적용** — 매 적용은 테이블 삭제+재생성+전체 규칙을 **단일 netlink 배치**로 커밋한다.
  부분 적용은 구조적으로 불가능하다: 이전 규칙 그대로거나, 새 규칙 전체거나.
- **실패 시 세대 동결** — 적용에 실패하면 보고 세대를 올리지 않고 다음 주기에 재시도한다.
- **입력은 방화벽 설정으로 취급** — 모든 값은 타입 파싱(`netip.Addr`, 포트 정수)되고, 대상
  CIDR 화이트리스트·공인 포트 대역·중복을 매 로드마다 재검증한다. 검증 실패 스냅샷은 적용되지
  않는다.
- **경계 있는 fail-open** — 마지막 적용 스냅샷을 상태 디렉터리에 보존(`persistedAt`+세대,
  temp+rename)하고, 부팅 시 그 나이가 허용 창(배포 시 플랫폼 IP 격리 창에 맞춰 지정, 현재 24h)
  이내일 때만 재적용한다. 창을 넘긴 스냅샷은 폐기하고 빈 집합으로 수렴한다(회수된 IP가 다른
  사용자에게 재할당됐을 수 있다).
- **netlink 직접 사용** — `nft(8)` 실행이 없어 자식 프로세스가 0개다. 덕분에 systemd 유닛이
  `SystemCallFilter`·`MemoryDenyWriteExecute`까지 켠 채 동작한다.

## 스냅샷 형식

sync 응답 본문 = `apply` 입력 파일 = 보존 파일(+`persistedAt`). 예시는 문서화 대역(RFC 5737)
주소를 쓴다.

```json
{ "generation": 42,
  "mappings": [
    { "id": 101, "proto": "tcp", "publicPort": 12345,
      "targetAddr": "192.0.2.23", "targetPort": 8080 } ] }
```

- `proto`: `tcp` | `udp` · `publicPort`: 릴레이 예약 대역 내(대역 하한 1024 — 저포트를
  DNAT으로 가리지 않도록) · `targetAddr`: 화이트리스트 CIDR 내 IPv4 · 동일 (proto,
  publicPort) 중복 금지.
- 정지(SUSPEND)된 매핑은 스냅샷에서 제외되어 내려온다 — 에이전트는 원하는 상태만 안다.

## 실행 모드

```
relay-agent apply -file snapshot.json   # 1회 적용 + 보존
relay-agent run                         # 부팅 재적용 → 폴링 루프
```

`run`의 HTTP sync 소스는 전송부 마일스톤에서 붙는다. 그 전까지는
`PICKLE_RELAY_SOURCE_FILE`로 로컬 파일을 폴링한다.

## 환경 변수

방화벽을 결정하는 값에는 **코드 기본값이 없다** — 없으면 기동을 거부한다(fail-closed).

| 변수 | 필수 | 설명 |
|---|---|---|
| `PICKLE_RELAY_TARGET_CIDR` | ✔ | DNAT 대상 화이트리스트 CIDR (IPv4) |
| `PICKLE_RELAY_PUBLIC_BAND` | ✔ | 공인 포트 대역 `MIN-MAX` |
| `PICKLE_RELAY_PUBLIC_IFACE` | ✔ | DNAT을 걸 공인 인터페이스 이름 |
| `STATE_DIRECTORY` | ✔ | 보존 스냅샷 위치 (systemd `StateDirectory=`가 주입) |
| `PICKLE_RELAY_SNAPSHOT_MAX_AGE_HOURS` | ✔ | 부팅 재적용 허용 창 — 플랫폼 IP 격리 창에 고정(방화벽 형성 값이라 기본값 없음) |
| `PICKLE_RELAY_POLL_SECONDS` | | 폴링 주기 (기본 15, 5–300) |
| `PICKLE_RELAY_CT_MAX_PER_MAPPING` | | 매핑당 동시 연결 상한 `ct count over N drop` (기본 512, `0`=비활성) |
| `PICKLE_RELAY_NEW_CONN_RATE` | | 매핑당 신규 연결 pps 상한 `limit rate over R/second` (기본 200, `0`=비활성) |
| `PICKLE_RELAY_NEW_CONN_BURST` | | 위 rate의 버스트 허용치 (기본 400) |
| `PICKLE_RELAY_SOURCE_FILE` | | 파일 소스 경로 (전송부 도입 전 필수) |

배포 값은 `/etc/pickle/relay-agent.env`(root 소유 640)에 둔다 — 저장소에는 없다.

가드 3종은 **조이는 방향(drop 상한)만** 하므로 기본값이 방화벽을 넓히지 않는다 — 그래서
위 필수 4종과 달리 기본값이 허용된다. **값 선정은 코드보다 중요한 운영 결정**이다.

- `ct count`는 **살아있는 연결이 아니라 conntrack 엔트리 수**를 센다(TIME_WAIT 포함). 따라서
  매핑당 정상 지속 한도 ≈ `ct 상한 ÷ TCP TIME_WAIT 수명`이다. 릴레이는 TIME_WAIT를 30s로
  낮춰(순수 NAT 포워더) 512 상한에서 매핑당 약 17 conn/s를 견디며, 버스트는 rate 가드의 버스트
  허용치가 흡수한다. 짧은 연결이 잦은 서비스(keep-alive 없는 HTTP 등)를 매핑에 얹으면 이 한도를
  기준으로 값을 올려야 한다.
- 가드 규칙에는 counter가 붙어(`… over N counter drop`) 드롭이 관측된다 — 정상 트래픽 오탐과
  실제 공격을 구분하는 신호이자 향후 heartbeat/자동 SUSPEND의 입력이다.
- 기본값은 **전역 conntrack 포화로 사용자 SSH가 막히는 것을 방지**하도록 잡았다. 실측: 가드 없이
  대량 UDP 플러드가 상태 테이블을 채워 :22 신규 접속을 차단했으나, 가드 활성 시 동일 플러드에도
  매핑 conntrack 발자국이 버스트 수준으로 유계·SSH 무영향.

## 구성 요소·버전

| 구성 요소 | 버전 | 근거 |
|---|---|---|
| Go | 1.26 | 플랫폼 표준 툴체인 |
| github.com/google/nftables | v0.3.0 | netlink 직접 제어 (최신 안정, 2026-07 확인) |

## 빌드·검증

```
scripts/build.sh        # dist/relay-agent (정적, CGO 없음)
scripts/verify.sh       # shellcheck + gofmt/vet/build/test + 공개 위생 스캔
scripts/setup-hooks.sh  # pre-commit(시크릿 스캔) + commit-msg(형식) 훅 설치
```

## systemd 유닛

`scripts/systemd/relay-agent.service` — 전용 사용자 `pickle-relay` +
`AmbientCapabilities=CAP_NET_ADMIN`이 전부다(root 아님). 자식 프로세스가 없으므로
`SystemCallFilter=@system-service`·`MemoryDenyWriteExecute=yes`를 포함한 전체 하드닝
블록이 적용된다. exec 헬퍼를 추가하려면 이 블록을 먼저 재검토할 것.

## 커밋 규약

커밋 메시지는 `type: subject` 형식(영어 명령형, 72자 이내, 마침표 없음)을 따르며 git 훅이
이를 강제한다. type은 `feat`, `fix`, `docs`, `test`, `chore`, `refactor`, `perf`,
`build`, `style`, `ci`, `revert` 중 하나. `scripts/verify.sh` 녹색 후 커밋한다. 위생
스캔(내부 경로·토큰 금지)은 verify에 포함되어 있으며 테스트 픽스처는 RFC 5737 문서화 주소만
쓴다.
