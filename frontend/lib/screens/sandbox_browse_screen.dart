// =============================================================================
// lib/screens/sandbox_browse_screen.dart
// 역할: 직접 탐방 모드 — kasmweb/chromium 컨테이너의 KasmVNC URL을 WebView로 로드해
//       사용자가 서버 위 격리 Chromium을 원격 조종하는 화면.
//
// [프록시 아키텍처]
// kasmweb은 6901(HTTPS+WSS)만 사용한다. 백엔드가 TCP SSL-strip 프록시를 동작시켜
// Flutter는 http:// (plain HTTP/WS)로 접속한다.
//
// noVNC WebSocket 경로: noVNC URL에 host/port/encrypt=0 파라미터를 명시해
// 프록시 포트로 ws:// 연결하도록 강제한다 (KasmVNC 커스텀 빌드가 wss:// 를 기본값으로
// 쓰는 경우 대비). onReceivedServerTrustAuthRequest를 추가해 noVNC가 직접
// wss:// 로 연결하는 경우에도 자체서명 인증서 거부가 발생하지 않도록 한다.
// =============================================================================

import 'dart:collection';

import 'package:flutter/material.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

import '../services/api_service.dart';

class SandboxBrowseScreen extends StatefulWidget {
  /// 원본 피싱 의심 URL (AppBar 표시용)
  final String url;

  /// 백엔드 SSL-strip 프록시 URL — WebView가 실제로 로드하는 주소 (HTTP)
  final String novncUrl;

  /// 컨테이너 종료 시 사용할 Docker 컨테이너 ID
  final String containerId;

  /// 컨테이너 종료 시 삭제할 Docker 네트워크 이름
  final String networkName;

  const SandboxBrowseScreen({
    super.key,
    required this.url,
    required this.novncUrl,
    required this.containerId,
    required this.networkName,
  });

  @override
  State<SandboxBrowseScreen> createState() => _SandboxBrowseScreenState();
}

class _SandboxBrowseScreenState extends State<SandboxBrowseScreen> {
  bool _isLoading = true;
  String? _errorMessage;
  bool _sessionExpired = false;
  bool _voteDone = false;
  bool _loadStarted = false;


  @override
  void dispose() {
    // fire-and-forget: 실패해도 앱 크래시 없음. 서버 타임아웃이 백업으로 동작.
    ApiService.terminateBrowseSession(widget.containerId, widget.networkName);
    super.dispose();
  }

  // ── 투표 모달 ─────────────────────────────────────────────────────────────

  Future<bool> _showVoteModal() async {
    if (_voteDone) return true;

    final result = await showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1F2937),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Row(
          children: [
            Icon(Icons.how_to_vote_rounded, color: Color(0xFF60A5FA), size: 22),
            SizedBox(width: 8),
            Text(
              '방문해 보니 어땠어요?',
              style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.w700),
            ),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              '다른 사용자에게도 도움이 돼요. 1초만 알려주세요.',
              style: TextStyle(color: Color(0xFF9CA3AF), fontSize: 13, height: 1.5),
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: _voteButton(
                    ctx, 'safe',
                    icon: Icons.check_circle_outline,
                    label: '괜찮아요',
                    color: const Color(0xFF10B981),
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: _voteButton(
                    ctx, 'spam',
                    icon: Icons.campaign_outlined,
                    label: '광고/스팸',
                    color: const Color(0xFFF59E0B),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 10),
            Row(
              children: [
                Expanded(
                  child: _voteButton(
                    ctx, 'danger',
                    icon: Icons.dangerous_rounded,
                    label: '위험해요',
                    color: const Color(0xFFDC2626),
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: _voteButton(
                    ctx, 'unsure',
                    icon: Icons.help_outline,
                    label: '잘 모르겠어요',
                    color: const Color(0xFF9CA3AF),
                  ),
                ),
              ],
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, null),
            child: const Text('건너뛰기', style: TextStyle(color: Color(0xFF6B7280))),
          ),
        ],
      ),
    );

    if (result != null && mounted) {
      setState(() => _voteDone = true);
      ApiService.submitVote(widget.url, widget.containerId, result);
    }
    return true;
  }

  Widget _voteButton(
    BuildContext ctx,
    String value, {
    required IconData icon,
    required String label,
    required Color color,
  }) {
    return OutlinedButton.icon(
      onPressed: () => Navigator.pop(ctx, value),
      icon: Icon(icon, size: 18),
      label: Text(label, style: const TextStyle(fontSize: 12)),
      style: OutlinedButton.styleFrom(
        foregroundColor: color,
        side: BorderSide(color: color),
        padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 4),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
      ),
    );
  }

  Future<void> _exitWithVote() async {
    await _showVoteModal();
    if (mounted) {
      // 직접 탐방 종료 → 모드 선택 화면을 건너뛰고 곧장 홈으로 복귀 (UX: 사용자 통제·자유).
      Navigator.popUntil(context, (route) => route.isFirst);
    }
  }


  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) async {
        if (didPop) return;
        await _showVoteModal();
        if (mounted) {
          Navigator.popUntil(context, (route) => route.isFirst);
        }
      },
      child: Scaffold(
      backgroundColor: const Color(0xFF111827),
      appBar: AppBar(
        backgroundColor: const Color(0xFF1F2937),
        foregroundColor: Colors.white,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: _exitWithVote,
        ),
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              '안전한 가상 화면',
              style: TextStyle(
                fontSize: 14,
                fontWeight: FontWeight.w700,
                color: Colors.white,
              ),
            ),
            Text(
              widget.url,
              style: const TextStyle(fontSize: 11, color: Color(0xFF9CA3AF)),
              overflow: TextOverflow.ellipsis,
            ),
          ],
        ),
        actions: [
          TextButton.icon(
            onPressed: _exitWithVote,
            icon: const Icon(Icons.stop_circle_outlined, size: 18, color: Color(0xFFF87171)),
            label: const Text(
              '나가기',
              style: TextStyle(color: Color(0xFFF87171), fontSize: 13),
            ),
          ),
        ],
      ),
      body: Column(
        children: [
          _buildWarningBanner(),
          Expanded(child: _buildBody()),
        ],
      ),
    ),
    );
  }

  Widget _buildWarningBanner() {
    return Container(
      width: double.infinity,
      color: const Color(0xFFDC2626),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      child: const Row(
        children: [
          Icon(Icons.warning_amber_rounded, color: Colors.white, size: 18),
          SizedBox(width: 8),
          Expanded(
            child: Text(
              '여기는 안전한 임시 화면이에요. 실제 정보(전화번호·계좌·비밀번호)는 입력하지 마세요.',
              style: TextStyle(
                color: Colors.white,
                fontSize: 12,
                fontWeight: FontWeight.w600,
                height: 1.4,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBody() {
    return Stack(
      children: [
        InAppWebView(
          initialUrlRequest: URLRequest(url: WebUri(widget.novncUrl)),
          // noVNC가 wss:// 를 강제 사용하는 경우에 대비해 ws:// 로 재작성한다.
          // AT_DOCUMENT_START 에서 WebSocket 생성자를 가로채므로 noVNC JS 실행 전에 적용된다.
          initialUserScripts: UnmodifiableListView([
            UserScript(
              source: r'''
                (function() {
                  // ── 공통: pathname에서 /novnc 까지의 경로를 추출 ──────────────
                  // 예: /sandbox/browse/abc123/novnc/ → pathBase = /sandbox/browse/abc123/novnc
                  var pathMatch = window.location.pathname.match(/(.*\/novnc)/);
                  var pathBase  = pathMatch ? pathMatch[1] : '';

                  // ── 1. WebSocket URL 재작성 ───────────────────────────────────
                  // noVNC가 wss://host:kasmPort/... 로 직접 연결 시도 → SSL 인증서 오류.
                  // FastAPI 백엔드 경유 아키텍처에서는 WS 목적지를
                  //   ws://SERVER:8000/sandbox/browse/{id}/novnc
                  // 로 재작성해야 FastAPI WS 프록시 핸들러에 도달한다.
                  // AT_DOCUMENT_START로 서버사이드 주입보다 먼저 실행되어 __shP 플래그로
                  // 중복 패치를 방지한다.
                  if (!window.WebSocket || !window.WebSocket.__shP) {
                    var _WS = window.WebSocket;
                    var proxyBase = window.location.protocol.replace('http', 'ws')
                                    + '//' + window.location.host + pathBase;
                    window.WebSocket = new Proxy(_WS, {
                      construct: function(target, args) {
                        if (typeof args[0] === 'string') {
                          // pathBase가 이미 URL에 포함된 경우 재작성 생략.
                          // noVNC가 path= URL 파라미터를 읽어 올바른 프록시 경로로
                          // 연결할 때 이중 경로가 생기는 것을 방지한다.
                          if (pathBase && args[0].indexOf(pathBase) !== -1) {
                            console.log('[SecurityHub] WS skip(ok): ' + args[0]);
                          } else {
                            var orig = args[0];
                            // wss?://any-host:any-port → ws://SERVER:8000/sandbox/browse/{id}/novnc
                            args[0] = args[0].replace(/^wss?:\/\/[^\/]*/, proxyBase);
                            if (orig !== args[0])
                              console.log('[SecurityHub] WS rewrite: ' + orig + ' → ' + args[0]);
                            else
                              console.log('[SecurityHub] WS: ' + orig);
                          }
                        }
                        return Reflect.construct(target, args);
                      }
                    });
                    window.WebSocket.__shP = 1;
                  }

                  // ── 2. fetch / XMLHttpRequest 절대경로 재작성 ─────────────────
                  // kasmVNC noVNC JS가 /api/statistics 등 절대경로로 API를 호출하면
                  // FastAPI 404 가 반환된다. 절대경로를 /sandbox/browse/{id}/novnc 기준으로
                  // 재작성해 FastAPI HTTP 프록시를 통해 kasmVNC에 전달한다.
                  // __shP2 플래그로 서버사이드 주입(</head> 직전)과 중복 패치를 방지한다.
                  if (!window.__shP2) {
                    window.__shP2 = 1;
                    if (pathBase) {
                      var _f = window.fetch;
                      if (_f) {
                        window.fetch = function(u, i) {
                          if (typeof u === 'string' && u[0] === '/' && u[1] !== '/') u = pathBase + u;
                          return _f.call(this, u, i);
                        };
                      }
                      var _x = XMLHttpRequest.prototype.open;
                      XMLHttpRequest.prototype.open = function(m, u, a, us, p) {
                        if (typeof u === 'string' && u[0] === '/' && u[1] !== '/') u = pathBase + u;
                        return _x.call(this, m, u, a, us, p);
                      };
                      console.log('[SecurityHub] fetch/XHR rewrite active, prefix=' + pathBase);
                    }
                  }
                })();
              ''',
              injectionTime: UserScriptInjectionTime.AT_DOCUMENT_START,
            ),
          ]),
          initialSettings: InAppWebViewSettings(
            javaScriptEnabled: true,
            useWideViewPort: true,
            loadWithOverviewMode: true,
            // 백엔드 프록시가 HTTP 제공 → cleartext 허용 필요
            mixedContentMode: MixedContentMode.MIXED_CONTENT_ALWAYS_ALLOW,
            mediaPlaybackRequiresUserGesture: false,
            transparentBackground: false,
            supportZoom: false,
          ),
          onWebViewCreated: (controller) {
            debugPrint('[SandboxBrowse] 로드 URL: ${widget.novncUrl}');
            // ── 세션 종료 감지 핸들러 ─────────────────────────────────────
            // JS 측에서 window.flutter_inappwebview.callHandler('onVncDisconnect')
            // 를 호출하면 Flutter 오버레이로 전환한다.
            controller.addJavaScriptHandler(
              handlerName: 'onVncDisconnect',
              callback: (_) {
                if (mounted && !_sessionExpired) {
                  setState(() => _sessionExpired = true);
                }
              },
            );
          },
          // KasmVNC 자체서명 SSL 인증서 신뢰 — 직접 wss:// 연결 시 cert 오류 방지
          onReceivedServerTrustAuthRequest: (controller, challenge) async {
            debugPrint(
              '[SandboxBrowse] SSL 인증 챌린지: ${challenge.protectionSpace.host}:${challenge.protectionSpace.port}',
            );
            return ServerTrustAuthResponse(
              action: ServerTrustAuthResponseAction.PROCEED,
            );
          },
          // kasmweb KasmVNC HTTP Basic Auth 자동 응답
          // 기본값: username=kasm_user, password=VNC_PW(sandbox)
          onReceivedHttpAuthRequest: (controller, challenge) async {
            debugPrint('[SandboxBrowse] HTTP 인증 챌린지: ${challenge.protectionSpace.host}:${challenge.protectionSpace.port} realm="${challenge.protectionSpace.realm}"');
            return HttpAuthResponse(
              username: 'kasm_user',
              password: 'sandbox',
              action: HttpAuthResponseAction.PROCEED,
            );
          },
          onConsoleMessage: (controller, msg) {
            debugPrint('[KasmVNC JS ${msg.messageLevel}] ${msg.message}');
          },
          onLoadStart: (_, __) {
            if (mounted) setState(() {
              _isLoading = true;
              _loadStarted = true;  // ← 추가
            });
          },
          onLoadStop: (controller, url) async {
            if (mounted) setState(() => _isLoading = false);
            // noVNC UI 초기화 대기 후 메뉴 숨김 + 터치 설정 주입
            await Future.delayed(const Duration(seconds: 1));
            if (!mounted) return;

            // ── 세션 종료 감지 JS 주입 ──────────────────────────────────
            // noVNC disconnect 상태 또는 Kasm 재연결 UI를 감지하면
            // Flutter 핸들러(onVncDisconnect)를 호출한다.
            // - 초기 30초는 VNC 연결 안정화 대기 (오감지 방지)
            // - 이후 8초 간격 폴링 + DOM MutationObserver 이중 감지
            try {
              await controller.evaluateJavascript(source: r'''
                (function monitorVncSession() {
                  var _notified = false;
                  function notify() {
                    if (_notified) return;
                    _notified = true;
                    try {
                      window.flutter_inappwebview.callHandler('onVncDisconnect');
                    } catch(e) {}
                  }

                  // 폴링: noVNC 상태 텍스트 + Kasm 재연결 오버레이 검사
                  function checkState() {
                    if (_notified) return;
                    var status = document.getElementById('noVNC_status');
                    if (status) {
                      var t = (status.textContent || '').toLowerCase();
                      if (t.indexOf('disconnect') !== -1 || t.indexOf('failed') !== -1) {
                        notify(); return;
                      }
                    }
                    // Kasm 유휴 타임아웃 오버레이 감지
                    var body = document.body || {};
                    var bodyText = (body.innerText || '').toLowerCase();
                    if ((bodyText.indexOf('session') !== -1) &&
                        (bodyText.indexOf('expired') !== -1 ||
                         bodyText.indexOf('timeout') !== -1 ||
                         bodyText.indexOf('idle') !== -1)) {
                      notify(); return;
                    }
                    setTimeout(checkState, 8000);
                  }
                  setTimeout(checkState, 30000);

                  // MutationObserver: Kasm이 동적으로 오버레이 삽입할 때 즉시 감지
                  if (window.MutationObserver) {
                    new MutationObserver(function(mutations) {
                      if (_notified) return;
                      mutations.forEach(function(m) {
                        m.addedNodes.forEach(function(node) {
                          if (node.nodeType !== 1) return;
                          var t = (node.innerText || node.textContent || '').toLowerCase();
                          if ((t.indexOf('session') !== -1) &&
                              (t.indexOf('expired') !== -1 ||
                               t.indexOf('timeout') !== -1 ||
                               t.indexOf('idle') !== -1)) {
                            notify();
                          }
                        });
                      });
                    }).observe(document.body || document.documentElement,
                      { childList: true, subtree: true });
                  }
                })();
              ''');
            } catch (e) {
              debugPrint('[SandboxBrowse] 세션 감지 JS 실패: $e');
            }

            try {
              await controller.evaluateJavascript(source: r'''
                (function() {
                  // ── 1. CSS로 즉시 숨김 ──────────────────────────────────
                  var s = document.createElement('style');
                  s.id = '_kasm_hide';
                  s.textContent =
                    '#noVNC_control_bar_anchor,' +
                    '#noVNC_control_bar,' +
                    '#noVNC_control_bar_handle,' +
                    '.noVNC_control_bar_handle,' +
                    '#noVNC_status_bar,' +
                    '#noVNC_logo, .noVNC_logo,' +
                    '#noVNC_bell,' +
                    '#noVNC_connect_controls,' +
                    '.noVNC_drag_handle,' +
                    '#kasm_toolbar, .kasm_toolbar,' +
                    '[class*="kasm"][class*="toolbar"],' +
                    '[id*="kasm"][id*="toolbar"],' +
                    // KasmVNC 커서 오버레이: 탭 후 overlay 위에 생겨 이후 터치를 가로챔
                    '#noVNC_cursor,.noVNC_cursor,' +
                    '[id*="cursor"],[class*="novnc_cursor"],[class*="kasm_cursor"]' +
                    '{ display:none !important; pointer-events:none !important; }';
                  document.head && document.head.appendChild(s);

                  // ── 2. MutationObserver: 동적으로 추가되는 요소도 즉시 숨김 ─
                  var HIDE = [
                    '#noVNC_control_bar_anchor',
                    '#noVNC_control_bar_handle',
                    '.noVNC_control_bar_handle',
                    '#noVNC_status_bar',
                    '#noVNC_bell',
                    '#noVNC_connect_controls',
                    '.noVNC_drag_handle',
                    '#kasm_toolbar',
                    '.kasm_toolbar'
                  ];
                  function hideAll() {
                    HIDE.forEach(function(sel) {
                      document.querySelectorAll(sel).forEach(function(el) {
                        el.style.setProperty('display', 'none', 'important');
                      });
                    });
                  }
                  hideAll();
                  if (window.MutationObserver) {
                    new MutationObserver(hideAll).observe(
                      document.documentElement,
                      { childList: true, subtree: true, attributes: true,
                        attributeFilter: ['style', 'class'] }
                    );
                  }

                  // ── 2.5. noVNC 다이얼로그 한국화 + Kasm 브랜딩 숨김 ──────
                  // Reconnecting/Disconnected 등 영어 다이얼로그가 동적으로 뜨는데
                  // ID/class가 빌드별로 달라 selector 일괄 숨김이 어렵다.
                  // → TreeWalker로 텍스트 노드를 순회해 한국어로 치환하고,
                  //   img/svg 중 alt·src에 'kasm'/'novnc' 포함된 것만 표시 제거한다.
                  var KASM_REPLACE = {
                    'Reconnecting...': '다시 연결 중이에요...',
                    'Reconnecting': '다시 연결 중이에요',
                    'Disconnected': '연결이 끊어졌어요',
                    'Connecting...': '연결 중이에요...',
                    'Cancel': '취소',
                    'Try Again': '다시 시도',
                    'Authentication failure': '인증에 실패했어요',
                    'Session expired': '세션이 종료됐어요',
                    'Idle timeout': '오래 사용하지 않아 종료됐어요'
                  };
                  // "KasmVNC" 브랜드 텍스트 노드를 발견하면 ancestor를 4단계까지 따라
                  // 올라가며 reconnect/status dialog 컨테이너 전체를 숨긴다.
                  // (로고 SVG는 형제 element에 있어서 직접 부모만 hide하면 잔존하기 때문)
                  function hideKasmAncestor(node) {
                    var p = node.parentElement;
                    for (var i = 0; i < 4 && p; i++) {
                      // dialog/status로 보이는 컨테이너는 통째로 가린다.
                      var cls = (p.className && p.className.toString && p.className.toString()) || '';
                      var id  = p.id || '';
                      if (/(dialog|status|reconnect|disconnect|panel|overlay|popup|modal)/i.test(cls + ' ' + id)) {
                        p.style.setProperty('display', 'none', 'important');
                        return;
                      }
                      p = p.parentElement;
                    }
                    // 매칭되는 ancestor가 없으면 직접 부모만 숨김 (fallback).
                    if (node.parentElement) {
                      node.parentElement.style.setProperty('display', 'none', 'important');
                    }
                  }
                  function localizeKasm() {
                    try {
                      var w = document.createTreeWalker(
                        document.body || document.documentElement,
                        NodeFilter.SHOW_TEXT, null
                      );
                      var n;
                      while ((n = w.nextNode())) {
                        var v = n.nodeValue;
                        if (!v) continue;
                        var t = v.trim();
                        if (!t) continue;
                        if (t.indexOf('KasmVNC') !== -1 || t.toLowerCase().indexOf('kasmvnc') !== -1) {
                          hideKasmAncestor(n);
                          continue;
                        }
                        if (KASM_REPLACE[t]) {
                          n.nodeValue = v.replace(t, KASM_REPLACE[t]);
                        }
                      }
                      document.querySelectorAll('img, svg').forEach(function(el) {
                        var alt = (el.getAttribute('alt') || el.getAttribute('aria-label') || '').toLowerCase();
                        var src = (el.getAttribute('src') || '').toLowerCase();
                        if (alt.indexOf('kasm') !== -1 || src.indexOf('kasm') !== -1 ||
                            alt.indexOf('novnc') !== -1 || src.indexOf('novnc') !== -1) {
                          el.style.setProperty('display', 'none', 'important');
                        }
                      });
                    } catch(e) {}
                  }

                  // 한글 IME 입력 시도: compositionend로 합성된 한글 음절을
                  // InputEvent로 다시 dispatch해 noVNC keyboard handler가 처리하도록 한다.
                  // (RFB 프로토콜 한계로 100% 보장은 아니지만 일부 빌드에서 동작)
                  function attachImeHandler() {
                    var ki = document.getElementById('noVNC_keyboardinput');
                    if (!ki || ki.__shIME) return;
                    ki.__shIME = 1;
                    ki.addEventListener('compositionend', function(e) {
                      if (!e.data) return;
                      try {
                        var ev = new InputEvent('input', {
                          bubbles: true, cancelable: true,
                          inputType: 'insertText', data: e.data
                        });
                        ki.dispatchEvent(ev);
                      } catch(err) {}
                    });
                  }
                  attachImeHandler();
                  setTimeout(attachImeHandler, 1000);
                  setTimeout(attachImeHandler, 3000);
                  localizeKasm();
                  if (window.MutationObserver) {
                    new MutationObserver(localizeKasm).observe(
                      document.body || document.documentElement,
                      { childList: true, subtree: true, characterData: true }
                    );
                  }

                  // ── 3. 포인터 락 방지 ────────────────────────────────────
                  // KasmVNC는 mousedown 후 canvas.requestPointerLock()을 호출한다.
                  // Pointer lock이 활성화되면 이후 터치 이벤트가 canvas로 캡처돼
                  // overlay가 이벤트를 받지 못하고 드래그(WheelEvent)가 멈춘다.
                  // pointerlockchange에서 즉시 exitPointerLock()해 이를 원천 차단한다.
                  document.addEventListener('pointerlockchange', function() {
                    if (document.pointerLockElement) document.exitPointerLock();
                  }, true);

                  // ── 4. 모바일 터치 오버레이 ──────────────────────────────
                  // noVNC 캔버스 위에 투명 div를 씌워 터치 이벤트를 가로챈다.
                  // noVNC의 기본 터치 핸들러(커서 드래그)가 실행되지 않으며,
                  // 스와이프 → 스크롤 휠 / 탭 → 마우스 클릭 으로 직접 변환한다.
                  // canvas는 noVNC 재연결·resize=remote 처리 시 교체될 수 있다.
                  // 클로저가 옛 canvas를 캡처하면 교체 후 이벤트가 사라진 요소로
                  // 전달돼 터치가 먹히지 않는다.
                  // → 이벤트마다 getCanvas()로 현재 canvas를 재조회하고,
                  //   MutationObserver로 canvas 교체를 감지해 overlay를 재설치한다.
                  (function setupOverlay() {
                    var OV_ID = '_mobile_ov';

                    function getCanvas() {
                      return document.getElementById('noVNC_canvas') ||
                             document.querySelector('canvas');
                    }

                    function fire(type, cx, cy, extra) {
                      var c = getCanvas();
                      if (!c) return;
                      c.dispatchEvent(new MouseEvent(type, Object.assign(
                        { bubbles: true, clientX: cx, clientY: cy }, extra
                      )));
                    }

                    function attach() {
                      var canvas = getCanvas();
                      if (!canvas) { setTimeout(attach, 400); return; }
                      if (document.getElementById(OV_ID)) return;

                      var container = canvas.parentElement || document.body;
                      if (getComputedStyle(container).position === 'static')
                        container.style.position = 'relative';

                      var ov = document.createElement('div');
                      ov.id = OV_ID;
                      // z-index를 최댓값으로 설정해 KasmVNC가 동적으로 삽입하는
                      // 커서 오버레이·툴팁 등 모든 요소보다 항상 위에 위치하도록 한다.
                      ov.style.cssText =
                        'position:absolute;inset:0;z-index:2147483647;touch-action:none;';
                      container.appendChild(ov);

                      var sx, sy, lx, ly, isTap;
                      var TAP_PX = 10, SCROLL_SCALE = 3;
                      var scrollAccum = 0, scrollTimer = null;
                      // tapUpTimer: mousedown 전송 후 mouseup 예약 타이머.
                      // null이면 현재 마우스 버튼이 눌린 상태가 아님을 의미한다.
                      var tapUpTimer = null;

                      function flushScroll() {
                        scrollTimer = null;
                        if (Math.abs(scrollAccum) < 1) return;
                        var c = getCanvas();
                        if (c) c.dispatchEvent(new WheelEvent('wheel', {
                          bubbles: true, clientX: lx, clientY: ly,
                          deltaY: scrollAccum,
                          deltaMode: WheelEvent.DOM_DELTA_PIXEL
                        }));
                        scrollAccum = 0;
                      }

                      ov.addEventListener('touchstart', function(e) {
                        e.preventDefault();
                        var t = e.touches[0];
                        // 스크롤 타이머 취소 (델타는 버림 — 새 제스처 시작)
                        if (scrollTimer) { clearTimeout(scrollTimer); scrollTimer = null; }
                        scrollAccum = 0;
                        // tapUpTimer가 살아있으면 이전 탭의 mousedown이 아직
                        // 해제되지 않은 것 → 지금 위치에서 mouseup을 즉시 전송.
                        // 그 외에는 절대 mouseup을 보내지 않는다:
                        // 불필요한 mouseup이 noVNC 내부 상태를 바꿔
                        // WheelEvent 처리가 깨지는 원인이 된다.
                        if (tapUpTimer) {
                          clearTimeout(tapUpTimer);
                          tapUpTimer = null;
                          fire('mouseup', t.clientX, t.clientY, { button: 0, buttons: 0 });
                        }
                        sx = lx = t.clientX; sy = ly = t.clientY;
                        isTap = true;
                      }, { passive: false });

                      ov.addEventListener('touchmove', function(e) {
                        e.preventDefault();
                        var t = e.touches[0];
                        if (Math.abs(t.clientX - sx) > TAP_PX ||
                            Math.abs(t.clientY - sy) > TAP_PX) isTap = false;
                        scrollAccum += (ly - t.clientY) * SCROLL_SCALE;
                        lx = t.clientX; ly = t.clientY;
                        if (!scrollTimer) scrollTimer = setTimeout(flushScroll, 50);
                      }, { passive: false });

                      ov.addEventListener('touchend', function(e) {
                        e.preventDefault();
                        flushScroll();
                        if (isTap) {
                          // 탭: 커서 이동 → mousedown → 80ms 후 mouseup → mouseout
                          // mouseout은 탭 후 KasmVNC의 커서 추적 모드를 해제해
                          // 이후 WheelEvent 기반 스크롤이 정상 동작하도록 한다.
                          fire('mousemove', sx, sy);
                          fire('mousedown', sx, sy, { button: 0, buttons: 1 });
                          tapUpTimer = setTimeout(function() {
                            tapUpTimer = null;
                            fire('mouseup', sx, sy, { button: 0, buttons: 0 });
                            fire('mouseout', sx, sy, { buttons: 0 });
                          }, 80);
                        }
                      }, { passive: false });

                      ov.addEventListener('touchcancel', function(e) {
                        e.preventDefault();
                        if (scrollTimer) { clearTimeout(scrollTimer); scrollTimer = null; }
                        if (tapUpTimer) {
                          clearTimeout(tapUpTimer); tapUpTimer = null;
                          fire('mouseup', lx, ly, { button: 0, buttons: 0 });
                        }
                        scrollAccum = 0; isTap = false;
                      }, { passive: false });

                      // ※ MutationObserver로 canvas 제거 감지 후 overlay 재설치하는 로직 제거.
                      //   noVNC가 resize=remote 처리 중 canvas 속성/크기를 바꿀 때
                      //   MutationObserver가 오감지해 overlay를 삭제하고 400ms 공백이 생겨
                      //   첫 터치가 noVNC 기본 커서 핸들러로 빠지는 문제를 유발한다.
                      //   대신 이벤트 핸들러 내부에서 getCanvas()로 매번 재조회하므로
                      //   canvas가 교체되어도 overlay 재설치 없이 정상 동작한다.
                    }

                    attach();
                  })();
                })();
              ''');
              final diag = await controller.evaluateJavascript(source: r'''
                (function() {
                  var c = document.querySelector('canvas');
                  return JSON.stringify({
                    canvas: c ? c.width + 'x' + c.height : 'none',
                    title: document.title
                  });
                })()
              ''');
              debugPrint('[SandboxBrowse] 진단: $diag');
            } catch (e) {
              debugPrint('[SandboxBrowse] JS 실패: $e');
            }
          },
          onReceivedError: (controller, request, error) {
            debugPrint(
              '[SandboxBrowse] 로드 오류'
                  ' | mainFrame=${request.isForMainFrame}'
                  ' | loadStarted=$_loadStarted'
                  ' | url=${request.url}'
                  ' | ${error.type}: ${error.description}',
            );
            // onLoadStart가 이미 불렸으면 메인 URL은 정상 접속된 것
            // → 이후 에러는 서브리소스(외부 도메인 등) 오류이므로 오버레이 억제
            if (_loadStarted) return;
            if (mounted) {
              setState(() {
                _isLoading = false;
                _errorMessage = '페이지 로드 실패: ${error.description}';
              });
            }
          },
        ),
        if (_isLoading && _errorMessage == null && !_sessionExpired)
          Container(
            color: const Color(0xFF111827),
            child: const Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  CircularProgressIndicator(color: Color(0xFF60A5FA)),
                  SizedBox(height: 16),
                  Text(
                    '안전한 화면을 준비하고 있어요...',
                    style: TextStyle(color: Color(0xFF9CA3AF), fontSize: 13),
                  ),
                ],
              ),
            ),
          ),
        if (_sessionExpired) _buildSessionExpiredOverlay(),
        if (!_sessionExpired && _errorMessage != null) _buildErrorOverlay(),
      ],
    );
  }

  /// 세션 종료 오버레이 — Kasm 유휴 타임아웃 / VNC disconnect 감지 시 표시
  Widget _buildSessionExpiredOverlay() {
    return Container(
      color: const Color(0xFF111827),
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(28),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(
                Icons.timer_off_rounded,
                color: Color(0xFF6B7280),
                size: 52,
              ),
              const SizedBox(height: 20),
              const Text(
                '탐방을 마쳤어요',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 18,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 10),
              const Text(
                '한동안 사용이 없어\n화면이 자동으로 닫혔어요.',
                style: TextStyle(
                  color: Color(0xFF9CA3AF),
                  fontSize: 14,
                  height: 1.6,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 28),
              ElevatedButton.icon(
                onPressed: _exitWithVote,
                icon: const Icon(Icons.home_rounded),
                label: const Text('메인으로 돌아가기'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF2563EB),
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(
                    horizontal: 24,
                    vertical: 12,
                  ),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(10),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildErrorOverlay() {
    return Container(
      color: const Color(0xFF111827),
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(28),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(
                Icons.signal_wifi_off_rounded,
                color: Color(0xFFF87171),
                size: 48,
              ),
              const SizedBox(height: 16),
              Text(
                _errorMessage!,
                style: const TextStyle(
                  color: Color(0xFFFCA5A5),
                  fontSize: 13,
                  height: 1.5,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),
              ElevatedButton.icon(
                onPressed: () {
                  setState(() {
                    _isLoading = true;
                    _errorMessage = null;
                  });
                },
                icon: const Icon(Icons.refresh_rounded),
                label: const Text('다시 시도'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF2563EB),
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(
                    horizontal: 24,
                    vertical: 12,
                  ),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(10),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
