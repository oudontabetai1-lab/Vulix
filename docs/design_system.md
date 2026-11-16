# Vulix UI v3 Design System

Canonical reference guide for visual hierarchy, semantic tokens, data density, anti-patterns, and architectural decisions across the Vulix security inspection dashboard.

---

## 1. Visual Anti-Pattern Checklist

Security tooling demands maximum signal-to-noise ratio, deterministic readability, and zero cognitive fatigue during intense triage. Generic modern web templates often apply decorative flourishes ("AI slop") that impair data legibility, waste screen real estate, and degrade browser rendering performance.

Every UI component in Vulix must satisfy the following checklist.

| Pattern | Status | Criteria & Prohibited Forms | Allowed Uses & Exceptions | Exception Rationale |
|---|---|---|---|---|
| **Decorative Gradients ("AI Slop")** | **PROHIBITED** | Multi-stop linear/radial gradients, rainbow accents, iridescent button glows, animated gradient borders, diffuse colorful background blobs. | Flat surface elevation (`--surface`, `--surface2`), monochromatic progress bars using semantic status tokens (`--status-pass`, `--status-running`). | Security analysts require predictable luminance. Gradients reduce contrast readability of technical strings and distract from triage severity. |
| **Gratuitous Glass / Blur / Glow** | **PROHIBITED** | `backdrop-filter: blur()`, glowing drop-shadows (`box-shadow: 0 0 24px rgba(...)`), neon text shadows, transparent frosted panels over data tables. | Dark modal scrim overlays (`.ui-dialog-overlay` with solid or semi-transparent dark backdrop `rgba(0,0,0,0.6)`), crisp 2px focus rings (`--focus-ring`). | Blur shaders trigger GPU re-compositing bottlenecks during high-throughput event streaming (1,000+ SSE events/sec) and cause subpixel font anti-aliasing fuzziness. |
| **Uniform Large Border-Radius** | **PROHIBITED** | Mobile-style 16px–24px rounded corners applied to table containers, technical data cards, input fields, or dialog panes. | `4px` (`--space-xs`) for inputs and buttons; `6px`–`8px` for root container cards; `9999px` (pill) **strictly reserved** for status/severity chips (`.sev-badge`, `.verify-badge`). | Large radii create dead whitespace wedges in adjacent multi-column layouts, clipping technical payloads and table cells. |
| **Purposeless Card-in-Card Nesting** | **PROHIBITED** | Recursive container boxes (Card within Card within Card) with redundant borders, shadows, and compounding 16px/24px padding. | Flat semantic groups separated by single hairline 1px borders (`--border: #3f424d`) or subtle single-step surface elevation (`--surface2`). | Deep nesting squanders up to 25% of horizontal screen width on empty margins, forcing premature truncation of exploit URLs, headers, and payloads. |
| **Bento Grids Without Workflow Hierarchy** | **PROHIBITED** | Trendy asymmetric multi-cell grid boxes scattering metrics, graphs, logs, and actions into fragmented tiles without clear reading sequence. | Strict top-to-bottom and left-to-right operational workflow: Executive Summary / Target Scope at top -> Primary Actionable Table in center -> Collapsible Inspector on right. | Penetration testers scan top-down for critical findings. Unstructured mosaic grids break saccadic eye tracking and obscure operational priority. |
| **Mixed Icon Families** | **PROHIBITED** | Mixing line, solid, duotone, or cartoon icons; prepending decorative emojis ("🌐 Target:", "⚡ Payload:", "🛡️ Severity:") to standard labels. | Monochromatic 1.5px/2px stroke SVG icons from a unified set, or standard Unicode status glyphs (`✓ OK`, `⚠ Warning`, `✗ Fail`, `⟳ Running`) paired with text. | Inconsistent icon styles create visual chaos, cause baseline alignment mismatches in monospace tables, and fail screen reader accessibility if unlabelled. |
| **Vague CTA Labels** | **PROHIBITED** | Ambiguous one-word action buttons such as "Submit", "Action", "Do It", "Click Here", "Proceed", or "OK". | Explicit Verb + Noun labels: "Start Scan", "Rerun Preflight", "Clear Filters", "Copy Payload", "Export SARIF", "Add Account". | Destructive or resource-heavy actions (launching active crawl, resetting state) demand unambiguous intent confirmation before dispatch. |

---

## 2. Decoration & Semantic Color Separation

Vulix strictly isolates brand identity, vulnerability severity levels, execution/freshness states, and interactive selection states. **Never reuse a brand color to represent a severity or status, and never use a severity color for decorative brand elements.**

### Semantic Color Role Matrix

```
┌────────────────────────────────────────────────────────────────────────┐
│                        VULIX COLOR ROLE ISOLATION                      │
├──────────────────┬─────────────────┬──────────────────┬────────────────┤
│      BRAND       │    SEVERITY     │ EXECUTION STATE  │ SELECTION/FOCUS│
│  (--accent-*)    │  (--critical,   │ (--state-*,      │ (--focus-ring, │
│                  │   --high, etc.) │  --status-*)     │  --selection-*)│
├──────────────────┼─────────────────┼──────────────────┼────────────────┤
│ Purple (#9184d9) │ Red, Orange,    │ Green, Amber,    │ Accent Ring    │
│ Primary CTAs,    │ Yellow, Teal,   │ Blue-grey, Red   │ Active outline,│
│ Nav indicators   │ Vulnerability   │ Scan lifecycle,  │ keyboard focus │
│ (NEVER status)   │ impact only     │ data freshness   │ (interactive)  │
└──────────────────┴─────────────────┴──────────────────┴────────────────┘
```

1. **Brand Purple (`--accent-primary` / `--accent: #9184d9`)**:
   - **Allowed**: Primary action triggers, active navigation rail highlight, focused interactive control outlines.
   - **Prohibited**: Indicating finding severity (e.g. Info), representing scan success, or coloring execution states.
2. **Vulnerability Severities**:
   - **Critical (`--critical: #e2708f`)**: High-luminance soft crimson. Confirmed remote code execution, SQL injection, authentication bypass.
   - **High (`--high: #d99a63`)**: Vivid warm amber. High-impact unauthorized data exposure, SSRF, direct privilege escalation.
   - **Medium (`--medium: #c7b96a`)**: Warm ochre yellow. Reflected XSS, CSRF, sensitive misconfiguration.
   - **Low (`--low: #8fb9c9`)**: Cool slate cyan. Information disclosure, missing security headers with observable risk.
   - **Info (`--info: #b5abfc`)**: Lavender tint (distinct from brand purple `--accent-primary`). Informational observations, TLS certificate attributes.
3. **Execution & Freshness States**:
   - **Running (`--state-running` / `--status-running: #d99a63`)**: Active crawling or attack probe in-flight. Paired with `⟳` glyph and animated spin.
   - **Paused (`--state-paused`: `#c7b96a`)**: Execution suspended by user or schedule window.
   - **Completed / Pass (`--state-completed` / `--status-pass: #22c55e`)**: Verified clean probe, check passed, preflight readiness OK.
   - **Failed (`--state-failed` / `--status-fail: #e2708f`)**: Connection timeout, target crash, fatal engine error.
   - **Stale (`--state-stale` / `--status-stale: #d99a63`)**: Checkpoint data or cached finding requiring re-validation.
   - **Unverified (`--state-unverified: #8fb9c9`)**: Heuristic or agent-discovered finding pending deterministic confirmation.
4. **Active Selection & Focus Borders**:
   - `--focus-ring: 0 0 0 2px var(--accent)`: 2px offset solid focus ring providing instant keyboard navigation feedback.
   - `--focus-outline: 2px solid var(--accent)`: High-visibility focus indicator for native browser focus-visible.
   - `--selection-bg: rgba(145, 132, 217, 0.16)`: Row and node selection tint.
   - `--selection-border: #9184d9`: Selected card or table row indicator border.

### WCAG 2.2 AA Contrast Compliance Matrix

All text and interactive UI component boundaries are calibrated to meet or exceed **WCAG 2.2 Level AA requirements**:
- **Normal text (< 18px / 1.125rem non-bold)**: Minimum contrast ratio **$\ge 4.5:1$**.
- **Large text ($\ge 18px$ bold or $\ge 24px$) and UI component boundaries / badges**: Minimum contrast ratio **$\ge 3.0:1$**.

Measured contrast ratios against Vulix dark surfaces:
- Canvas background (`#0a0b10` / `--bg: #161826`)
- Container surface (`#12141d` / `--surface: #1c1e2c`)
- Elevated surface (`--surface2: #232532`)

| Token | Hex Value | Role | Ratio vs `#0a0b10` | Ratio vs `#12141d` | Ratio vs `#1c1e2c` | WCAG 2.2 AA Status |
|---|---|---|---|---|---|---|
| `--text` | `#e9e9ed` | Primary Body Text | **16.24:1** | **15.17:1** | **13.64:1** | PASS (Target: $\ge 4.5:1$) |
| `--text-muted` | `#9397ab` | Secondary / Metadata | **6.79:1** | **6.34:1** | **5.71:1** | PASS (Target: $\ge 4.5:1$) |
| `--accent-primary` | `#9184d9` | Brand Primary / Active | **6.09:1** | **5.69:1** | **5.12:1** | PASS (Target: $\ge 4.5:1$) |
| `--critical` | `#e2708f` | Severity: Critical | **6.50:1** | **6.08:1** | **5.46:1** | PASS (Target: $\ge 4.5:1$) |
| `--high` | `#d99a63` | Severity: High | **8.19:1** | **7.65:1** | **6.88:1** | PASS (Target: $\ge 4.5:1$) |
| `--medium` | `#c7b96a` | Severity: Medium | **9.90:1** | **9.25:1** | **8.32:1** | PASS (Target: $\ge 4.5:1$) |
| `--low` | `#8fb9c9` | Severity: Low | **9.32:1** | **8.70:1** | **7.83:1** | PASS (Target: $\ge 4.5:1$) |
| `--info` | `#b5abfc` | Severity: Info | **9.54:1** | **8.92:1** | **8.02:1** | PASS (Target: $\ge 4.5:1$) |
| `--status-pass` | `#22c55e` | State: Completed / Pass | **8.63:1** | **8.06:1** | **7.25:1** | PASS (Target: $\ge 4.5:1$) |
| `--state-unverified` | `#8fb9c9` | State: Unverified | **9.32:1** | **8.70:1** | **7.83:1** | PASS (Target: $\ge 4.5:1$) |
| `--state-running` | `#d99a63` | State: Running / In-Flight | **8.19:1** | **7.65:1** | **6.88:1** | PASS (Target: $\ge 4.5:1$) |
| `--selection-border`| `#9184d9` | UI Selection Border | **6.09:1** | **5.69:1** | **5.12:1** | PASS (Target: $\ge 3.0:1$) |

---

## 3. Typography & Data Density Guide

Vulix interfaces must display high volumes of heterogeneous security data: URL trees, parameter names, encoded exploit payloads, HTTP request/response headers, raw JSON bodies, and real-time event logs. Dense information presentation must be achieved through structured hierarchy and compact vertical rhythms rather than tiny, unreadable fonts.

### Font Families
- **System Sans (`--font-sans`)**:
  `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif`
  Used for interface chrome, view titles, navigation labels, button text, and descriptive prose.
- **System Monospace (`--font-mono`)**:
  `ui-monospace, "SF Mono", "Cascadia Code", "Source Code Pro", Menlo, Consolas, "DejaVu Sans Mono", monospace`
  Used for all security technical data: URLs, attack payloads, HTTP status codes, headers, JSON keys, hash digests, and CVSS scores.

### Type Scale & Hierarchy

| Token | Size (rem / px) | Weight | Line Height | Usage Scope & Constraints |
|---|---|---|---|---|
| `--text-2xs` / `--font-size-2xs` | `0.6875rem` / 11px (floor: `0.7rem`) | 600–700 | `1.25` | **Strictly reserved**: Compact badge counters, HTTP method chips (`GET`, `POST`), status code tags. Uppercase with `font-variant-numeric: tabular-nums`. NEVER used for body copy or labels > 8 chars. |
| `--text-xs` / `--font-size-xs` | `0.75rem` / 12px | 500–600 | `1.35` | **Minimum floor for readable labels**: Auxiliary table headers (`th`), timestamp strings, badge text, input helper hints, breadcrumb crumbs. |
| `--text-sm` / `--font-size-sm` | `0.8125rem` / 13px | 400–500 | `1.40` | Secondary metadata, parameter keys, table sub-rows, compact drawer field labels. |
| `--text-base` / `--font-size-base` | `0.875rem` / 14px | 400–500 | `1.50` | **Default body copy**: Form inputs, table data cells, primary modal text, button labels. |
| `--text-md` / `--font-size-md` | `1rem` / 16px | 500–600 | `1.50` | Subheadings, card titles, key metric summary values. |
| `--text-lg` / `--font-size-lg` | `1.125rem` / 18px (alias: `1.15rem`) | 600 | `1.35` | Section headers, panel titles, drawer sheet titles. |
| `--text-xl` | `1.25rem` / 20px | 600–700 | `1.30` | View headers, modal dialog titles. |
| `--text-2xl` | `1.5rem` / 24px | 700 | `1.25` | Top-level view title (e.g. Vulix header, portal welcome title). |

### Monospace Technical Data Rules
1. **Numeric Metrics**:
   - Must use `font-variant-numeric: tabular-nums;` to guarantee fixed-width character alignment across changing counter values and table columns.
2. **URLs, Parameters, and Payloads**:
   - Must specify:
     ```css
     font-family: var(--font-mono);
     overflow-wrap: anywhere;
     word-break: break-word;
     ```
   - In table rows: single-line clamp with text ellipsis (`white-space: nowrap; overflow: hidden; text-overflow: ellipsis;`), accompanied by native `title` attribute or click-to-expand drawer.
   - In detail drawer / evidence viewer: multi-line display with horizontal scroll (`overflow-x: auto;`) preserving raw payload whitespace.

### Data Density Scale
- **Compact Row Height (`--density-row-compact: 28px`)**:
  Used in high-volume tables (Traffic log, Crawl URL list, Raw audit stream). Padding: `4px 8px`, vertical gap: `4px`.
- **Standard Row Height (`--density-row-standard: 36px`)**:
  Used in primary triage tables (Findings overview, Scan history, Settings list). Padding: `8px 12px`, vertical gap: `8px`.
- **Spacing Scale**:
  `--space-xs: 4px;` | `--space-sm: 8px;` | `--space-md: 12px;` | `--space-lg: 16px;` | `--space-xl: 20px;` | `--space-2xl: 24px;` | `--space-3xl: 32px;`

---

## 4. Design Decision Log

Canonical record of architectural layout and interaction choices for each primary view in Vulix `/app`.

| View / Scope | User Task | Primary Emphasis | Visual / Interaction Order | Adopted Pattern | Rejected Template Alternative |
|---|---|---|---|---|---|
| **Overview (Portal / Home)** | Understand engine deployment state and launch quick tasks. | System readiness, active scan status, and primary navigational paths. | 1. Status banner -> 2. Primary action buttons -> 3. Recent activity summary. | Flat card layout with actionable status chips and direct route links. | Marketing hero banner with animated 3D graphics or carousel widgets. |
| **Scan Setup** | Configure scan target, check profiles, authentication, and preflight validation. | Configuration validation, scope definition, and preflight readiness verdict. | 1. Target URL & Scope inputs -> 2. Check selection matrix -> 3. Preflight readiness panel -> 4. "Start Scan" primary CTA. | Two-column responsive form with inline popover check help and sticky preflight validation drawer. | Multi-step wizard modal hiding earlier configuration options behind wizard step transitions. |
| **Live Monitor** | Monitor active crawl and attack phases in real time with high-velocity telemetry. | Real-time progress, error logs, and immediate vulnerability alerts. | 1. Top progress/ETA bar -> 2. Left Event log (terminal-style) -> 3. Center workspace tabs -> 4. Right live findings rail. | Persistent 3-pane synchronized dashboard with WebSockets and paused/scrolling event log controls. | Single-column linear event feed requiring endless manual scrolling to locate discovered findings. |
| **Crawl** | Inspect discovered attack surface, route trees, forms, and parameter nodes. | Site topology, node vulnerability overlay, and crawl completeness. | 1. Breadcrumb filter toolbar -> 2. Interactive SVG crawl graph -> 3. Node details table & inspector. | Dual-mode topology: interactive visual SVG graph connected to filterable URL/form data table. | Disconnected static tree view with no visual link between endpoints and injection parameters. |
| **Findings** | Triage, verify, and export detected security vulnerabilities. | Finding severity, reproduction evidence, and verification status. | 1. Severity filter pills -> 2. Search & group toolbar -> 3. Virtualized findings data table -> 4. Slide-over Evidence Drawer. | Master-detail split layout: compact table rows with expandable side drawer containing raw HTTP request/response. | Full-page navigation for each finding that destroys analyst filter context and scroll position. |
| **Traffic** | Inspect intercepted HTTP request/response pairs, payloads, and timing. | Raw HTTP fidelity, status codes, payload mutations, and latency. | 1. Method/Status filter bar -> 2. Compact traffic data table (`28px` rows) -> 3. Side-by-side Request/Response viewer. | High-density tabular stream with syntax-highlighted monospace inspector and copy-as-curl action. | Chunky card list with hidden request/response bodies requiring modal clicks for every entry. |
| **Reports** | Review historical scan runs, download SARIF/JSON/HTML reports, and compare diffs. | Report artifact downloads, scan outcome diffs, and compliance summaries. | 1. Run selector -> 2. Summary scorecards -> 3. Download action bar -> 4. Compliance mapping tables. | Clean tabular audit ledger with direct file download links and visual severity distribution bars. | Heavily animated infographic charts with un-copyable numbers and missing raw export links. |
| **Settings** | Configure API keys, LLM backend roles, MCP tools, and scan defaults. | Predictable configuration schema editing without accidental secret leaks. | 1. Grouped settings navigation -> 2. Form fields with inline defaults -> 3. Secret mask/reveal toggles -> 4. Save indicator. | Grouped form cards with clear help tooltips, masked password inputs, and instant schema validation feedback. | Uncategorized single massive form with unmasked sensitive credential inputs. |
