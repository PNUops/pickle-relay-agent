# pickle-relay-agent

부산대학교 클라우드 플랫폼(Pickle)의 포트포워딩 릴레이에서 nftables DNAT을 제어하는
에이전트입니다.

플랫폼이 정의한 "원하는 매핑 집합"(공인 포트 → VM 포트)을 받아, 오프캠퍼스 릴레이
호스트의 방화벽을 그 상태로 수렴시킵니다. 왼쪽에서 스냅샷이 들어와 오른쪽 커널 규칙이
됩니다.

```
플랫폼 API ── 매핑 스냅샷(JSON, generation 태그) ──▶ relay-agent ──▶ nftables (netlink)
```

에이전트는 스냅샷을 만들지 않고 받기만 합니다. 무엇을 열지는 플랫폼이 정합니다.

현재는 `PICKLE_RELAY_SOURCE_FILE`이 가리키는 로컬 파일을 폴링합니다. HTTP 동기화는 아직
제공하지 않습니다.

## 지향하는 바

- 호스트의 다른 방화벽 설정을 침범하지 않는 범위를 유지합니다.
- 절반만 적용된 상태가 생기지 않도록 고민합니다.
- 들어오는 값을 방화벽 설정으로 취급해 매번 다시 검증합니다.
- 자식 프로세스 없이 도는 상태를 유지해 systemd 하드닝을 최대로 켭니다.

## 동작 방식

- **자기 테이블만 소유합니다.** `ip pickle_relay_dnat` 하나만 만들고 교체합니다. 룰셋
  전체 flush는 코드에 없습니다. 정적 배관 테이블은 호스트 부팅 설정이 소유합니다.
- **적용은 원자적입니다.** 테이블 삭제, 재생성, 전체 규칙을 단일 netlink 배치로
  커밋합니다. 이전 규칙 전체이거나 새 규칙 전체이거나 둘 중 하나입니다.
- **실패하면 세대를 올리지 않습니다.** 보고 세대를 그대로 두고 다음 주기에 재시도합니다.
- **입력을 매번 검증합니다.** 모든 값을 타입 파싱(`netip.Addr`, 포트 정수)하고 대상
  CIDR 화이트리스트, 공인 포트 대역, 중복 여부를 매 로드마다 다시 확인합니다.
- **fail-open에 경계가 있습니다.** 마지막 적용 스냅샷을 보존해 두고 부팅 때
  재적용하는데, 나이가 허용 창(현재 24h, 플랫폼의 IP 격리 창과 같은 값)을 넘겼으면
  폐기하고 빈 집합으로 수렴합니다. 회수된 IP가 그 사이 다른 사용자에게 재할당됐을 수
  있기 때문입니다.
- **netlink를 직접 씁니다.** `nft(8)`를 실행하지 않아 자식 프로세스가 없고, systemd
  유닛이 `SystemCallFilter=@system-service`와 `MemoryDenyWriteExecute=yes`를 켠 채
  돕니다. exec 헬퍼를 추가한다면 이 하드닝 블록부터 다시 봐야 합니다.
- **방화벽을 결정하는 값에는 기본값이 없습니다.** 대상 CIDR, 공인 대역, 인터페이스,
  스냅샷 허용 창은 없으면 기동을 거부합니다.

## 스냅샷 형식

sync 응답 본문, `apply` 입력 파일, 보존 파일이 모두 같은 형태입니다. 예시는 문서화
대역(RFC 5737) 주소를 씁니다.

```json
{ "generation": 42,
  "mappings": [
    { "id": 101, "proto": "tcp", "publicPort": 12345,
      "targetAddr": "192.0.2.23", "targetPort": 8080 } ] }
```

`proto`는 `tcp` 또는 `udp`입니다. `publicPort`는 릴레이 예약 대역 안이어야 하고 대역
하한은 1024입니다. `targetAddr`는 화이트리스트 CIDR 안의 IPv4이며, 같은
(proto, publicPort) 중복은 허용하지 않습니다. 정지된 매핑은 스냅샷에서 빠진 채로
내려옵니다.

## 실행 모드

```
relay-agent apply -file snapshot.json   # 1회 적용 + 보존
relay-agent run                         # 부팅 재적용 → 폴링 루프
```

## 남용 가드

매핑마다 `ct count`(동시 연결 상한)와 신규 연결 rate limit이 붙습니다. 세 가드 모두
조이는 방향(drop 상한)만 있어 기본값이 방화벽을 넓히지 않습니다.

`ct count`가 세는 것은 살아 있는 연결이 아니라 conntrack 엔트리 수이고 TIME_WAIT도
포함합니다. 그래서 매핑당 정상 지속 한도는 대략 `상한 ÷ TIME_WAIT 수명`입니다. 릴레이는
순수 NAT 포워더라 TIME_WAIT를 30초로 두고 있어, 기본 상한 512에서 매핑당 초당 17연결
정도를 견딥니다. 짧은 연결이 잦은 서비스를 얹는다면 이 값을 기준으로 상한을 올리세요.

`NEW_CONN_BURST=0`은 "버스트 없음"이 아니라 커널이 5패킷 허용치로 보정하는 값입니다.
대역에 릴레이 자체 서비스 포트가 들어 있으면 기동을 거부합니다. 가드 규칙에는 counter를
붙여 드롭이 관측되므로, 정상 트래픽 오탐과 실제 차단을 구분할 수 있습니다.

## 구성

| 변수 | 필수 | 설명 |
|---|---|---|
| `PICKLE_RELAY_TARGET_CIDR` | ✔ | DNAT 대상 화이트리스트 CIDR (IPv4) |
| `PICKLE_RELAY_PUBLIC_BAND` | ✔ | 공인 포트 대역 `MIN-MAX` |
| `PICKLE_RELAY_PUBLIC_IFACE` | ✔ | DNAT을 걸 공인 인터페이스 |
| `PICKLE_RELAY_SNAPSHOT_MAX_AGE_HOURS` | ✔ | 부팅 재적용 허용 창. IP 격리 창에 맞춥니다 |
| `STATE_DIRECTORY` | ✔ | 보존 스냅샷 위치 (systemd `StateDirectory=` 주입) |
| `PICKLE_RELAY_SOURCE_FILE` | | 파일 소스 경로 |
| `PICKLE_RELAY_POLL_SECONDS` | | 폴링 주기 (기본 15) |
| `PICKLE_RELAY_CT_MAX_PER_MAPPING` | | 매핑당 conntrack 상한 (기본 512, `0`이면 끔) |
| `PICKLE_RELAY_NEW_CONN_RATE` / `_BURST` | | 매핑당 신규 연결 pps 상한과 버스트 (기본 200/400) |

배포 값은 `/etc/pickle/relay-agent.env`(root 640)에 둡니다. 이 저장소에는 없습니다.

## 시작하기

```
scripts/setup-hooks.sh  # 최초 1회: pre-commit(시크릿 스캔) + commit-msg(형식) 훅
scripts/verify.sh       # shellcheck + gofmt/vet/build/test + 공개 위생 스캔
scripts/build.sh        # dist/relay-agent (정적, CGO 없음)
```

Go 1.26이 필요하고 직접 의존성은 `github.com/google/nftables` v0.3.0 하나입니다.
`scripts/systemd/relay-agent.service`는 전용 사용자 `pickle-relay`에
`AmbientCapabilities=CAP_NET_ADMIN`만 부여합니다.

## 관련 저장소

| 저장소 | 역할 |
|---|---|
| [pickle-api](https://github.com/PNUops/pickle-api) | REST API와 프로비저닝 워커 (Spring Boot 4, Java 25, PostgreSQL 18, JobRunr) |
| [pickle-console](https://github.com/PNUops/pickle-console) | 사용자·관리자 웹 콘솔 (React 19, TypeScript) |
| [pickle-sshgw](https://github.com/PNUops/pickle-sshgw) | SSH 게이트웨이와 웹 터미널 브리지 (sshpiperd, Go) |
| [pickle-proxy-agent](https://github.com/PNUops/pickle-proxy-agent) | nginx 리버스 프록시 제어 에이전트 (Go) |
| [pickle-relay-agent](https://github.com/PNUops/pickle-relay-agent) | 오프캠퍼스 릴레이의 nftables DNAT 에이전트 (Go) |
| [pickle-infra](https://github.com/PNUops/pickle-infra) (비공개) | 인프라 프로비저닝 스크립트와 운영 런북 (shell) |
| [pickle-infra-example](https://github.com/PNUops/pickle-infra-example) | 프로비저닝·배포 스크립트와 런북 샘플 |
| [pickle-secrets](https://github.com/PNUops/pickle-secrets) (비공개) | 호스트 시크릿 볼트 (git-crypt) |
| [pickle-secrets-example](https://github.com/PNUops/pickle-secrets-example) | 볼트 레이아웃과 git-crypt 운용 절차 |

## 커밋 규약

`type: subject` 형식, 영어 명령형, 72자 이내입니다. commit-msg 훅이 강제합니다. 테스트
픽스처는 RFC 5737 문서화 주소만 씁니다. 커밋 전에 `scripts/verify.sh`가 녹색이어야
합니다.

## 라이선스

MIT
