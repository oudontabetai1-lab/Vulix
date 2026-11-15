/** 共有検査項目カタログと説明ポップオーバー。 */
(function (global) {
  'use strict';
  const cache = {};
  let nextId = 0;

  const FEATURE_HELP_CATALOG = {
    ja: {
      mode_normal: {
        title: '通常スキャン (Normal Mode)',
        short_description: '決定論スキャナによる確実性重視のスキャンモード',
        meaning: '決定論的ルールスキャナがクロールおよびペイロード注入を行い、再現・確証が取れた脆弱性のみを厳密に報告します。',
        impact: 'CI/CDパイプラインや定期セキュリティ診断など、誤検知（False Positive）を極小化して確実に対処を進めたい場面に最適です。',
        limitations: 'あらかじめ定義されたルールやシグネチャに基づくため、複数画面を横断する複雑な業務ロジック不備の網羅的発見には限界があります。'
      },
      mode_agent: {
        title: 'Agentスキャン (Agent Mode)',
        short_description: 'LLMがブラウザを自律操作して探索・攻撃を行うモード',
        meaning: '大規模言語モデル（LLM）がWeb画面の構造や文脈を解釈し、自律的にブラウザを操作して脆弱性の仮説検証と深層探索を行います。',
        impact: '人間のペネトレーションテスターのように複数ステップの入力フローや動的SPAの隠れた機能を自律的に深掘りし、未知の攻撃経路を発見します。',
        limitations: '実行に時間を要し、LLM APIトークンコストが発生します。また決定論的検証を経ていない仮説的指摘を含む場合があります。'
      },
      mode_hybrid: {
        title: 'Hybridスキャン (Hybrid Mode)',
        short_description: 'Agentの広域探索と決定論スキャナの確実性を統合したモード',
        meaning: 'LLM Agentが高度な画面遷移・API偵察（Recon）を行って攻撃対象を洗い出し、決定論スキャナが精密なペイロード検証を実施して併記します。',
        impact: '広範なクロール到達性と高い検出確証性を両立し、Agentの発見仮説も明示ラベル付きで消さずに保持します。',
        limitations: 'ReconフェーズとAttackフェーズの両方を実行するため、高速性が求められる軽量スキャンには不向きです。'
      },
      scope_target_vs_access: {
        title: 'ターゲットURLとアクセスURLのスコープ境界',
        short_description: '能動的攻撃対象（Target）と受動的探索のみ（Access）の分離境界',
        meaning: 'target_urlsは脆弱性検査ペイロードを能動的に投入する対象です。access_urlsはクロール・リンク収集のために訪問・参照するのみで注入を行いません。',
        impact: '外部IdPや決済API、ログアウトリンクなど、攻撃を投入してはならないエンドポイントを安全にスコープから保護できます。',
        limitations: 'access_urlsに指定されたドメインやパスは脆弱性検査がスキップされるため、その領域の不備は検出されません。'
      },
      crawl_depth_concurrency: {
        title: 'クロール深さと並行ワーカー数',
        short_description: '探索階層の深さ（Depth）と並行実行ブラウザ数（Concurrency）の制御',
        meaning: 'Depthは起点URLからのリンク探索階層の上限を指定し、Concurrencyは同時に起動するPlaywright Chromiumブラウザワーカーの数を指定します。',
        impact: 'ターゲットサーバへの負荷（リクエストレート）を抑えつつ、必要な探索網羅性と実行完了時間のバランスを最適化します。',
        limitations: 'Depthを過大に設定すると巨大な動的サイトで探索が発散し、Concurrencyが高すぎるとWAFやレートリミットを誘発します。'
      },
      preflight_gate: {
        title: 'スキャン事前検証ゲート (Preflight Gate)',
        short_description: 'スキャン開始前に対象の到達性・証明書・セッションを確認する安全機構',
        meaning: 'スキャン本格開始前に、対象URLへのHTTP/HTTPS疎通、TLS証明書の妥当性、基本ヘッダ応答、認証エンドポイントの有効性を自動確認します。',
        impact: '誤ったURL設定やサーバダウン、認証設定ミスによる無駄なスキャン実行やエラー報告の乱造を未然に防止します。',
        limitations: '事前検証時のネットワーク一時障害やWAFの初期拒否により、正常なスキャン開始がブロックされることがあります。'
      },
      auth_login_verification: {
        title: 'ログイン自動検証 (Login Verification)',
        short_description: 'フォーム・API自動ログインの実行と多面的証拠によるセッション確認',
        meaning: '設定された資格情報で自動ログインを試行し、Cookie残存・リダイレクト・保護リソース応答など独立した2つ以上の証拠で成否を厳密に判定します。',
        impact: 'ログイン後の管理者ページや会員専用領域を、セッション切れを起こさずに確実に検査対象に含めることができます。',
        limitations: '画像CAPTCHAやスライドアクションなど完全な人間操作を強制する認証機構は自動通過できません。'
      },
      mfa_totp_mcp: {
        title: 'MFA/2FA自動解決 (TOTP & Email MCP)',
        short_description: '外部MCP連携によるTOTP・Emailワンタイムコードの自動取得',
        meaning: '多要素認証（MFA）が有効な環境に対し、Model Context Protocol (MCP) を通じてTOTP生成器やIMAPメール受信サーバからワンタイムコードを自動取得・注入します。',
        impact: 'MFAが必須のステージング環境や本番類似環境でも、人間の介入なしに夜間バッチや自動診断を完走できます。',
        limitations: '有効なTOTPシークレット鍵、またはMCP email-serverの接続設定とメール受信権限が事前に必要です。'
      },
      credential_redaction: {
        title: '認証情報の自動マスク (Credential Redaction)',
        short_description: 'パスワードやトークン、Cookieなどの機密値をUIおよびログから自動秘匿',
        meaning: 'URLクエリ、Basic認証ヘッダ、Bearerトークン、Cookie、POSTボディ内のパスワード文字列を検出時に自動で<redacted>に置換します。',
        impact: '画面共有時や監査ログのエクスポート時、レポート共有時に平文の機密認証情報が外部に漏洩するリスクをゼロにします。',
        limitations: '特殊なプロプライエタリ形式の独自トークンは、追加のカスタム正規表現ルールを指定しないとマスクされない場合があります。'
      },
      provenance_deterministic_vs_agent: {
        title: '検出の出自 (Provenance: Scanner vs Agent)',
        short_description: '決定論スキャナによる確証検出とLLM Agentによる仮説的発見の区分',
        meaning: 'scannerは決定論スキャナがペイロード注入と応答検証で実証した検出です。agentはLLMが自律探索中に発見した脆弱性仮説（未確証含む）です。',
        impact: '再現性が確立された確実な不備と、Agentの文脈分析に基づく洞察的指摘をトリアージ担当者が混同せずに優先度付けできます。',
        limitations: 'Agent指摘は独自の発見価値が高い一方、通常の決定論検査と比較して偽陽性（誤検知）の比率が高くなる傾向があります。'
      },
      verification_confirmed_vs_unconfirmed: {
        title: '検証状態 (Verification: Confirmed vs Unconfirmed)',
        short_description: '再検証プローブによる再現成功（Confirmed）と未確証（Unconfirmed）の状態',
        meaning: '検出された脆弱性が独立した検証リクエストによって確実に再現・証明されたか、または一時的シグナルに留まるかの分類です。',
        impact: '開発チームやセキュリティ担当者は、Confirmed（確証済み）の脆弱性に優先してリソースを投入し、迅速な修正を進められます。',
        limitations: 'CSRFトークン消費やデータベース状態変化に依存する脆弱性は、自動再検証プローブが失敗してUnconfirmedとなる場合があります。'
      },
      finding_triage_status: {
        title: 'トリアージ状態 (Finding Triage Status)',
        short_description: '脆弱性指摘に対するレビューおよび対応ステータス管理',
        meaning: '指摘ごとに「未レビュー (unreviewed)」「確認済み (confirmed)」「誤検知 (false_positive)」「受容 (accepted)」「修正済み (fixed)」を管理します。',
        impact: '次回スキャン実行時や差分スキャン（Diff Scan）時に、既知の受容済みリスクや対処済み項目との比較を正確に行えます。',
        limitations: 'トリアージ記録は検出重複キー（Dedup Key）に紐づくため、エンドポイントURLやパラメータ名が大きく改変されると再レビューが必要です。'
      },
      status_execution_vs_connection: {
        title: '実行状態と通信状態の分離 (Execution vs Connection)',
        short_description: 'スキャンプロセスの実行状態とブラウザ-サーバ間のWebSocket通信状態の明確な区分',
        meaning: 'スキャンの実行状態（running / done / aborted / error）と、ダッシュボードとサーバを結ぶリアルタイム通信状態（connected / reconnecting / disconnected）は独立しています。',
        impact: '一時的なネットワーク切断やWi-Fi断（disconnected）が発生しても、バックエンドのスキャンは中断されずに継続していることを正しく把握でき、完了と誤認することを防ぎます。',
        limitations: 'disconnected状態の間はダッシュボードの表示メトリクスが一時停止し、再接続成功時に最新スナップショットが同期されます。'
      },
      freshness_live_vs_stale: {
        title: 'データ鮮度 (Data Freshness: Live vs Stale vs Snapshot)',
        short_description: '表示されているメトリクスがリアルタイム同期中か過去のスナップショットかの判別',
        meaning: 'freshは現在進行中のスキャンからリアルタイムイベントを受信中、staleは通信断または更新遅延中、snapshotは完了済み過去スキャンの静的記録です。',
        impact: '操作者が「現在動いているスキャンのライブ情報」を見ているのか「過去の保存結果」を見ているのかを直感的に識別できます。',
        limitations: '極端に高いトラフィック時や大量のイベント受信時は、ブラウザの描画キュー処理により数秒程度のイベント遅延が生じる場合があります。'
      },
      partial_incomplete_scan: {
        title: '不完全スキャン状態 (Partial / Incomplete Scan)',
        short_description: '中断・エラー・時間制限等により一部の検査のみが完了した状態',
        meaning: 'ユーザーの中断操作（Abort）、時間帯制限（Time Window）、または例外エラー等により、全検査計画の一部しか消化されずに終了した状態を示します。',
        impact: '一部のみ検査された結果を「全体が安全」と誤解することを防ぎ、チェックポイント（Checkpoint）からの再開スキャンを促します。',
        limitations: '不完全スキャンで検出されなかった脆弱性は「存在しない」のではなく「検査が未到達」であるため、安全性の証明にはなりません。'
      }
    },
    en: {
      mode_normal: {
        title: 'Normal Mode',
        short_description: 'Deterministic scanning prioritizing certainty and low false positives',
        meaning: 'The deterministic scanner drives crawling and payload injection, reporting only strictly reproduced and verified vulnerabilities.',
        impact: 'Ideal for CI/CD pipelines and recurring compliance audits where minimizing false positives is critical.',
        limitations: 'Limited to predefined signature rules; complex multi-step business logic flaws may not be detected.'
      },
      mode_agent: {
        title: 'Agent Mode',
        short_description: 'Autonomous LLM-driven browser penetration testing and exploration',
        meaning: 'Large Language Models autonomously interpret page semantics and drive browser interactions to hypothesize and probe vulnerabilities.',
        impact: 'Uncovers complex interaction flows and hidden single-page application paths like an experienced human penetration tester.',
        limitations: 'Slower execution and higher LLM token consumption; reports may include unconfirmed hypotheses.'
      },
      mode_hybrid: {
        title: 'Hybrid Mode',
        short_description: 'Combines autonomous Agent reconnaissance with deterministic verification',
        meaning: 'The LLM Agent performs wide reconnaissance and endpoint discovery, followed by deterministic scanner payload validation.',
        impact: 'Maximizes crawl coverage while retaining deterministic finding certainty, presenting both side-by-side with provenance labels.',
        limitations: 'Executes both reconnaissance and attack passes, requiring more total scan duration than a standard scan.'
      },
      scope_target_vs_access: {
        title: 'Target vs Access Scope Boundary',
        short_description: 'Defines boundaries between active injection (Target) and passive discovery (Access)',
        meaning: 'target_urls receive active vulnerability payloads. access_urls are navigated and crawled for links only without injection.',
        impact: 'Protects critical external integrations, payment processors, and logout buttons from unintentional payload execution.',
        limitations: 'Endpoints designated as access_urls are not tested for vulnerabilities, leaving flaws in those domains unexamined.'
      },
      crawl_depth_concurrency: {
        title: 'Crawl Depth & Concurrency',
        short_description: 'Controls page traversal depth and concurrent browser workers',
        meaning: 'Depth sets the maximum link distance from seeds. Concurrency sets the number of parallel Playwright browser instances.',
        impact: 'Regulates scan duration and server request pressure, ensuring balanced coverage without overwhelming targets.',
        limitations: 'Excessive depth causes crawl explosions on dynamic sites; excessive concurrency can trigger rate limits or WAF bans.'
      },
      preflight_gate: {
        title: 'Preflight Gate Validation',
        short_description: 'Pre-scan health check verifying reachability, TLS, and session integrity',
        meaning: 'Automated validation of target URL reachability, TLS certificate validity, and authentication state before scanning begins.',
        impact: 'Prevents wasted scan runs and cascade failures caused by incorrect hostnames or expired login credentials.',
        limitations: 'Transient network glitches during preflight checks can temporarily delay or prevent scan initiation.'
      },
      auth_login_verification: {
        title: 'Login Verification',
        short_description: 'Automated login execution with multi-signal session verification',
        meaning: 'Executes automated authentication via forms or APIs, verifying active sessions with at least two independent proof signals.',
        impact: 'Guarantees authenticated scanning of protected member areas without dropping active sessions midway.',
        limitations: 'Cannot solve interactive biometric challenges or graphical CAPTCHAs requiring human presence.'
      },
      mfa_totp_mcp: {
        title: 'MFA/2FA Automated Resolution (TOTP & Email MCP)',
        short_description: 'Automated retrieval of MFA one-time passcodes via external MCP servers',
        meaning: 'Resolves multi-factor authentication by requesting one-time codes from TOTP authenticators or IMAP email servers via MCP.',
        impact: 'Enables fully unattended vulnerability scanning even in staging and production environments protected by mandatory MFA.',
        limitations: 'Requires configured TOTP secret keys or accessible MCP email server credentials with inbox read permissions.'
      },
      credential_redaction: {
        title: 'Credential Redaction',
        short_description: 'Automatic sanitization of secrets, tokens, and credentials from UI and logs',
        meaning: 'Automatically replaces passwords, API keys, Bearer tokens, cookies, and sensitive parameters with <redacted>.',
        impact: 'Eliminates accidental credential leakage during screen-sharing, team collaboration, or audit log exports.',
        limitations: 'Proprietary non-standard token patterns may require custom sanitization regex configurations.'
      },
      provenance_deterministic_vs_agent: {
        title: 'Finding Provenance (Scanner vs Agent)',
        short_description: 'Distinguishes between deterministic scanner findings and LLM Agent hypotheses',
        meaning: 'scanner findings are validated by deterministic payload probes. agent findings represent LLM-originated hypotheses.',
        impact: 'Enables triage engineers to immediately differentiate verified reproducible findings from exploratory agent insights.',
        limitations: 'Agent-originated insights provide valuable context but carry a higher probability of false positives than scanner findings.'
      },
      verification_confirmed_vs_unconfirmed: {
        title: 'Verification State (Confirmed vs Unconfirmed)',
        short_description: 'Indicates whether a finding was deterministically reproduced by verification probes',
        meaning: 'Confirmed findings were deterministically verified by independent reproduction steps. Unconfirmed findings showed single-event signals.',
        impact: 'Allows remediation teams to prioritize confirmed vulnerabilities immediately for patching.',
        limitations: 'Vulnerabilities depending on transient timing or CSRF token state may fail automated reproduction, remaining unconfirmed.'
      },
      finding_triage_status: {
        title: 'Finding Triage Status',
        short_description: 'Workflow lifecycle state management for detected vulnerabilities',
        meaning: 'Tracks each finding through unreviewed, confirmed, false_positive, accepted, and fixed statuses.',
        impact: 'Facilitates collaboration between security and engineering teams and informs diff scans against known accepted risks.',
        limitations: 'Triage records link to deduplication keys; substantial endpoint refactoring may require re-triaging.'
      },
      status_execution_vs_connection: {
        title: 'Execution vs Connection State',
        short_description: 'Explicit separation between backend scan execution and frontend WebSocket connection',
        meaning: 'Scan execution status (running/done/aborted/error) is distinct from frontend WebSocket transport state (connected/reconnecting/disconnected).',
        impact: 'Prevents operators from mistaking temporary network loss for scan completion, keeping status transparent.',
        limitations: 'Metrics are paused while disconnected and will catch up automatically once the WebSocket reconnects.'
      },
      freshness_live_vs_stale: {
        title: 'Data Freshness (Live vs Stale vs Snapshot)',
        short_description: 'Indicates whether displayed data is streaming live or loaded from historical snapshot',
        meaning: 'fresh means receiving real-time scan event streams; stale indicates connection delays; snapshot indicates historical scan data.',
        impact: 'Ensures operators always know if they are looking at live active telemetry or static archived records.',
        limitations: 'Under extreme traffic bursts, browser event rendering may introduce small buffering latency.'
      },
      partial_incomplete_scan: {
        title: 'Partial / Incomplete Scan State',
        short_description: 'Indicates that only a subset of planned security checks ran due to aborts or limits',
        meaning: 'Signals that a scan concluded prematurely due to operator abort, time-window restrictions, or runtime errors.',
        impact: 'Prevents assuming that partial scan results mean the entire application is secure, prompting checkpoint resumption.',
        limitations: 'Absence of findings in incomplete phases does not imply safety; unfinished checks must be resumed.'
      }
    }
  };

  function cleanText(text) {
    if (typeof text !== 'string') return '';
    return text.trim();
  }

  function normalizeReferences(rawRefs) {
    if (!Array.isArray(rawRefs)) return [];
    return rawRefs.filter(ref => {
      if (typeof ref !== 'object' || ref === null) return false;
      if (typeof ref.id !== 'string' || !ref.id.trim()) return false;
      if (typeof ref.kind !== 'string' || !ref.kind.trim()) return false;
      if (typeof ref.url !== 'string' || !ref.url.trim()) return false;
      try {
        const url = new URL(ref.url.trim());
        if (url.protocol !== 'https:') return false;
      } catch {
        return false;
      }
      return true;
    }).map(ref => ({
      kind: cleanText(ref.kind),
      id: cleanText(ref.id),
      url: cleanText(ref.url),
    }));
  }

  function emptyEntry(checkId) {
    return {
      title: checkId,
      short_description: 'Description not available yet',
      what_is_tested: '',
      risk_if_vulnerable: '',
      verification_overview: '',
      remediation_overview: '',
      limitations: '',
      references: [],
    };
  }

  function normalizeEntry(checkId, raw) {
    if (!raw) return emptyEntry(checkId);

    const references = normalizeReferences(raw.references);

    return {
      title: cleanText(raw.title || checkId),
      short_description: cleanText(raw.short_description),
      what_is_tested: cleanText(raw.what_is_tested),
      risk_if_vulnerable: cleanText(raw.risk_if_vulnerable),
      verification_overview: cleanText(raw.verification_overview),
      remediation_overview: cleanText(raw.remediation_overview),
      limitations: cleanText(raw.limitations),
      references,
    };
  }

  async function loadCatalog(api, lang) {
    const language = lang === 'en' ? 'en' : 'ja';
    if (!cache[language]) cache[language] = (async () => {
      try {
        const response = api && typeof api.get === 'function'
          ? await api.get(`/api/v1/check-catalog?lang=${language}`)
          : await fetch(`/api/v1/check-catalog?lang=${language}`);
        const data = response && response.data ? response.data : (response && response.ok ? await response.json() : null);
        return data && data.catalog_version === '1.0.0' && data.checks && typeof data.checks === 'object'
          ? data : { checks: {}, lang: language };
      } catch (_) { return { checks: {}, lang: language }; }
    })();
    return cache[language];
  }

  function closeAllPopovers(doc) {
    const contextDoc = doc || (typeof document !== 'undefined' ? document : null);
    if (!contextDoc || typeof contextDoc.querySelectorAll !== 'function') return;
    const oldPopovers = contextDoc.querySelectorAll('.setup-check-popover');
    oldPopovers.forEach((old) => {
      if (typeof old.closeHelp === 'function') {
        old.closeHelp();
      } else {
        old.remove();
      }
    });
  }

  function positionPopover(info, popover, doc) {
    const anchor = info.getBoundingClientRect();
    const box = popover.getBoundingClientRect();
    const viewportWidth = (global && global.innerWidth) || (doc.documentElement && doc.documentElement.clientWidth) || 1024;
    const viewportHeight = (global && global.innerHeight) || (doc.documentElement && doc.documentElement.clientHeight) || 768;

    let left = anchor.left;
    if (left + box.width > viewportWidth - 8) {
      left = viewportWidth - box.width - 8;
    }
    if (left < 8) left = 8;

    const belowSpace = viewportHeight - anchor.bottom - 6;
    let top;
    if (belowSpace < box.height && anchor.top - box.height - 6 >= 8) {
      top = anchor.top - box.height - 6;
    } else {
      top = Math.min(anchor.bottom + 6, viewportHeight - box.height - 8);
    }
    if (top < 8) top = 8;

    popover.style.position = 'fixed';
    popover.style.left = `${Math.round(left)}px`;
    popover.style.top = `${Math.round(top)}px`;
  }

  function createButton(doc, host, checkId, catalog, lang) {
    const language = lang === 'en' ? 'en' : 'ja';
    const entry = catalog && catalog[checkId];
    const normalized = entry ? normalizeEntry(checkId, entry) : emptyEntry(checkId);
    const fallback = language === 'en' ? 'Description not available yet' : '説明準備中';
    const title = normalized.title;

    const info = doc.createElement('button');
    info.type = 'button';
    info.className = 'setup-check-info';
    info.textContent = 'i';
    info.setAttribute('aria-label', `${title} ${language === 'en' ? 'description' : 'の説明'}`);
    info.title = normalized.short_description ? normalized.short_description : fallback;
    info.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      closeAllPopovers(doc);

      const popover = doc.createElement('section');
      popover.className = 'setup-check-popover';
      popover.setAttribute('role', 'dialog');
      const heading = doc.createElement('h3');
      heading.textContent = title;
      heading.id = `check-help-${++nextId}`;
      popover.setAttribute('aria-labelledby', heading.id);
      popover.appendChild(heading);

      const fields = [
        ['what_is_tested', '確認する内容', 'What is tested'],
        ['risk_if_vulnerable', '脆弱な場合のリスク', 'Risk if vulnerable'],
        ['verification_overview', '確認方法', 'Verification'],
        ['remediation_overview', '対処の概要', 'Remediation'],
        ['limitations', '制約', 'Limitations'],
      ];
      if (entry) fields.forEach(([key, ja, en]) => {
        const label = doc.createElement('h4');
        label.textContent = language === 'en' ? en : ja;
        const detail = doc.createElement('p');
        detail.textContent = normalized[key] || fallback;
        popover.append(label, detail);
      });

      if (!entry) {
        const detail = doc.createElement('p');
        detail.textContent = fallback;
        popover.appendChild(detail);
      }

      // References section
      if (entry && normalized.references && normalized.references.length > 0) {
        const refSection = doc.createElement('section');
        refSection.setAttribute('data-check-help-section', 'references');
        const refHeadingLang = language === 'en' ? 'References' : '参考情報';
        const refHeading = doc.createElement('h4');
        refHeading.textContent = refHeadingLang;
        refSection.appendChild(refHeading);

        const refList = doc.createElement('ul');
        refList.setAttribute('data-check-help-references', 'true');

        normalized.references.forEach(ref => {
          const listItem = doc.createElement('li');
          const link = doc.createElement('a');
          link.className = 'check-help-reference-link';
          link.target = '_blank';
          link.rel = 'noopener noreferrer';

          const id = ref.id;
          const linkText = id && !title.includes(id) ? `${id} ${title}` : title;

          link.textContent = linkText;
          link.href = ref.url;

          listItem.appendChild(link);
          refList.appendChild(listItem);
        });

        refSection.appendChild(refList);
        popover.appendChild(refSection);
      }
      const close = doc.createElement('button');
      close.type = 'button';
      close.className = 'setup-check-popover-close';
      close.textContent = language === 'en' ? 'Close' : '閉じる';
      let removeListeners = () => {};
      const closePopover = () => {
        popover.remove();
        removeListeners();
        info.focus();
      };
      popover.closeHelp = closePopover;
      close.addEventListener('click', closePopover);
      popover.appendChild(close);

      const targetHost = host || doc.body;
      targetHost.appendChild(popover);
      positionPopover(info, popover, doc);
      close.focus();

      const outside = (e) => { if (!popover.contains(e.target) && e.target !== info) closePopover(); };
      const escape = (e) => { if (e.key === 'Escape') closePopover(); };
      removeListeners = () => { doc.removeEventListener('pointerdown', outside); doc.removeEventListener('keydown', escape); };
      doc.addEventListener('pointerdown', outside);
      doc.addEventListener('keydown', escape);
    });
    return info;
  }

  function createHelpButton(doc, host, topicId, lang) {
    const language = lang === 'en' ? 'en' : 'ja';
    const cat = FEATURE_HELP_CATALOG[language] || FEATURE_HELP_CATALOG.ja || {};
    const fallbackCat = FEATURE_HELP_CATALOG.ja || {};
    const entry = cat[topicId] || fallbackCat[topicId] || {
      title: topicId,
      short_description: language === 'en' ? 'Feature details' : '機能の詳細',
      meaning: '',
      impact: '',
      limitations: '',
    };
    const title = entry.title || topicId;
    const fallback = language === 'en' ? 'Details not available yet' : '説明準備中';

    const info = doc.createElement('button');
    info.type = 'button';
    info.className = 'setup-check-info';
    info.textContent = 'i';
    info.setAttribute('data-help-topic', topicId);
    info.setAttribute('aria-label', `${title} ${language === 'en' ? 'help' : 'の説明'}`);
    info.title = entry.short_description || title;

    info.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      closeAllPopovers(doc);

      const popover = doc.createElement('section');
      popover.className = 'setup-check-popover';
      popover.setAttribute('role', 'dialog');
      const heading = doc.createElement('h3');
      heading.textContent = title;
      heading.id = `feature-help-${++nextId}`;
      popover.setAttribute('aria-labelledby', heading.id);
      popover.appendChild(heading);

      const fields = [
        ['meaning', '概要・意味', 'What it means'],
        ['impact', '用途と影響', 'Usage & Impact'],
        ['limitations', '制約事項', 'Limitations'],
      ];

      fields.forEach(([key, ja, en]) => {
        const val = entry[key] || (key === 'meaning' ? entry.what_is_tested : (key === 'impact' ? (entry.usage || entry.risk_if_vulnerable) : ''));
        if (val) {
          const label = doc.createElement('h4');
          label.textContent = language === 'en' ? en : ja;
          const detail = doc.createElement('p');
          detail.textContent = val;
          popover.append(label, detail);
        }
      });

      if (!entry.meaning && !entry.impact && !entry.limitations && !entry.what_is_tested) {
        const detail = doc.createElement('p');
        detail.textContent = fallback;
        popover.appendChild(detail);
      }

      if (entry.references && Array.isArray(entry.references) && entry.references.length > 0) {
        const refSection = doc.createElement('section');
        refSection.setAttribute('data-check-help-section', 'references');
        const refHeading = doc.createElement('h4');
        refHeading.textContent = language === 'en' ? 'References' : '参考情報';
        refSection.appendChild(refHeading);

        const refList = doc.createElement('ul');
        refList.setAttribute('data-check-help-references', 'true');

        entry.references.forEach((ref) => {
          const listItem = doc.createElement('li');
          const link = doc.createElement('a');
          link.className = 'check-help-reference-link';
          link.target = '_blank';
          link.rel = 'noopener noreferrer';
          link.textContent = ref.id ? `${ref.id} ${title}` : title;
          link.href = ref.url;
          listItem.appendChild(link);
          refList.appendChild(listItem);
        });

        refSection.appendChild(refList);
        popover.appendChild(refSection);
      }

      const close = doc.createElement('button');
      close.type = 'button';
      close.className = 'setup-check-popover-close';
      close.textContent = language === 'en' ? 'Close' : '閉じる';

      let removeListeners = () => {};
      const closePopover = () => {
        popover.remove();
        removeListeners();
        info.focus();
      };
      popover.closeHelp = closePopover;
      close.addEventListener('click', closePopover);
      popover.appendChild(close);

      const targetHost = host || doc.body;
      targetHost.appendChild(popover);
      positionPopover(info, popover, doc);
      close.focus();

      const outside = (e) => {
        if (!popover.contains(e.target) && e.target !== info) closePopover();
      };
      const escape = (e) => {
        if (e.key === 'Escape') closePopover();
      };
      removeListeners = () => {
        doc.removeEventListener('pointerdown', outside);
        doc.removeEventListener('keydown', escape);
      };
      doc.addEventListener('pointerdown', outside);
      doc.addEventListener('keydown', escape);
    });

    return info;
  }

  function attachHelpButtons(root, host, lang) {
    if (!root || typeof root.querySelectorAll !== 'function') return [];
    const elements = root.querySelectorAll('[data-help-topic]');
    const buttons = [];
    const doc = root.ownerDocument || (typeof document !== 'undefined' ? document : null);
    if (!doc) return [];
    elements.forEach((el) => {
      if (el.classList.contains('setup-check-info') || el.querySelector('.setup-check-info')) return;
      const topicId = el.getAttribute('data-help-topic');
      if (!topicId) return;
      const btn = createHelpButton(doc, host || el.parentElement || el, topicId, lang);
      el.appendChild(btn);
      buttons.push(btn);
    });
    return buttons;
  }

  const exported = { loadCatalog, createButton, createHelpButton, attachHelpButtons, FEATURE_HELP_CATALOG };
  if (typeof module !== 'undefined' && module.exports) module.exports = exported;
  global.VulixCheckHelp = exported;
})(typeof window !== 'undefined' ? window : globalThis);