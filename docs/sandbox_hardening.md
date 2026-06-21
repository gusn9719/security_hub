# 샌드박스 격리 강화 + 탈출시도 검증 결과 (DC-51)

`backend/tests/run_sandbox_escape_test.py` 실행 결과. 강화된 파라미터로
실제 7-A(kasmweb/chromium)/7-B(Browserless) 컨테이너를 띄운 뒤
`container.exec_run()`으로 호스트 침투를 시도했다.

## 적용된 강화 파라미터

| | 7-A (`browse_service.py`) | 7-B (`sandbox_service.py`) |
|---|---|---|
| mem_limit | 512m | 512m |
| nano_cpus | 0.5 코어 | 0.5 코어 |
| pids_limit | 256 | 128 |
| 포트 바인딩 | 127.0.0.1 (변경 전: 전체 노출) | 127.0.0.1 (기존 유지) |
| cap_drop | ALL | ALL |
| security_opt | no-new-privileges | no-new-privileges |

Kasm Chromium 1.14.0 / Browserless 둘 다 `cap_drop=["ALL"]` +
`security_opt=["no-new-privileges"]` 적용 후에도 noVNC 렌더링, CDP
원격 디버깅, Playwright 자동분석 전부 정상 동작 확인(별도 스모크 테스트,
`cap_add` 예외 불필요).

## 탈출시도 검증 결과 (11/11 차단)

| 영역 | 시도 | 기대 결과 | 실제 결과 | 판정 |
|---|---|---|---|---|
| 7-A-호스트FS | ls /host, mount | grep host | 마운트 없음 | ls: cannot access '/host': No such file or directory /dev/sdd on /etc/hostname type ext4 (rw,relatim | PASS (차단됨) |
| 7-A-DockerSocket | ls /var/run/docker.sock | 소켓 부재 | ls: cannot access '/var/run/docker.sock': No such file or directory | PASS (차단됨) |
| 7-A-SSRF(host.docker.internal) | curl host.docker.internal:8000 | 연결 실패 (0.0.0.0 매핑) | HTTP=000CURL_FAILED | PASS (차단됨) |
| 7-A-CapEff | cat /proc/self/status | grep CapEff | CapEff=0 (cap_drop=ALL) | CapEff:	0000000000000000 | PASS (차단됨) |
| 7-A-ForkBomb | sleep 2 & x768 | 프로세스 수 <= ~256 | 실제 프로세스 수=51 (요청=768) | PASS (차단됨) |
| 7-B-호스트FS | ls /host, mount | grep host | 마운트 없음 | ls: cannot access '/host': No such file or directory /dev/sdd on /etc/hostname type ext4 (rw,relatim | PASS (차단됨) |
| 7-B-DockerSocket | ls /var/run/docker.sock | 소켓 부재 | ls: cannot access '/var/run/docker.sock': No such file or directory | PASS (차단됨) |
| 7-B-SSRF(host.docker.internal) | curl host.docker.internal:8000 | 연결 실패 (0.0.0.0 매핑) | HTTP=000CURL_FAILED | PASS (차단됨) |
| 7-B-CapEff | cat /proc/self/status | grep CapEff | CapEff=0 (cap_drop=ALL) | CapEff:	0000000000000000 | PASS (차단됨) |
| 7-B-ForkBomb | sleep 2 & x384 | 프로세스 수 <= ~128 | 실제 프로세스 수=8 (요청=384) | PASS (차단됨) |
| ICC-차단 | ping 172.21.0.3 | ICC 차단으로 실패 | PING 172.21.0.3 (172.21.0.3): 56 data bytes  --- 172.21.0.3 ping statistics --- 1 packets transmitte | PASS (차단됨) |


## 한계

- ICC(컨테이너 간 통신) 테스트는 운영 코드가 세션마다 전용 네트워크를
  새로 생성하므로 실제로는 발생하지 않는 상황을 인위적으로 재현한 것이다
  — `enable_icc=false` 라는 방어선 자체가 살아있는지만 별도로 확인했다.
- 프로세스 폭탄 테스트는 컨테이너 baseline 프로세스 수(Xvnc·창관리자·
  Chromium 등)를 포함한 합계로 판정하므로 약간의 여유 마진을 둠
  (`pids_limit + 20`).
- Docker 컨테이너 경계 자체(커널 네임스페이스·cgroup) 너머의 커널
  0-day 취약점까지는 이 테스트로 증명할 수 없다 — 이건 모든 컨테이너
  기반 격리의 공통적 한계이며, 졸업작품 범위에서 추가로 줄일 수 있는
  부분은 아니다.
