"""Unit and catalog validation tests for VulixCheckHelp and FEATURE_HELP_CATALOG."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parent.parent

REQUIRED_TOPICS = [
    # 1) Scan Modes
    "mode_normal",
    "mode_agent",
    "mode_hybrid",
    # 2) Scope & Crawl
    "scope_target_vs_access",
    "crawl_depth_concurrency",
    "preflight_gate",
    # 3) Authentication & Session
    "auth_login_verification",
    "mfa_totp_mcp",
    "credential_redaction",
    # 4) Findings & Verification States
    "provenance_deterministic_vs_agent",
    "verification_confirmed_vs_unconfirmed",
    "finding_triage_status",
    # 5) Monitor / Connection / Freshness States
    "status_execution_vs_connection",
    "freshness_live_vs_stale",
    "partial_incomplete_scan",
]


def _run_node(code: str) -> dict:
    cmd = ["node", "-e", code]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=str(ROOT))
    return json.loads(res.stdout)


def test_feature_help_catalog_structure_and_completeness():
    """Verify that all 15 required feature help topics exist in both Japanese and English."""
    script = """
    const { FEATURE_HELP_CATALOG } = require('./templates/ui/check-help.js');
    console.log(JSON.stringify(FEATURE_HELP_CATALOG));
    """
    catalog = _run_node(script)

    assert "ja" in catalog
    assert "en" in catalog

    for lang in ("ja", "en"):
        for topic in REQUIRED_TOPICS:
            assert topic in catalog[lang], f"Topic '{topic}' missing in language '{lang}'"
            entry = catalog[lang][topic]
            assert isinstance(entry.get("title"), str) and len(entry["title"].strip()) > 0
            assert isinstance(entry.get("short_description"), str) and len(entry["short_description"].strip()) > 0
            assert isinstance(entry.get("meaning"), str) and len(entry["meaning"].strip()) > 0
            assert isinstance(entry.get("impact"), str) and len(entry["impact"].strip()) > 0
            assert isinstance(entry.get("limitations"), str) and len(entry["limitations"].strip()) > 0


def test_create_help_button_dom_structure():
    """Verify createHelpButton produces an accessible button element with correct metadata."""
    script = """
    const { createHelpButton, FEATURE_HELP_CATALOG } = require('./templates/ui/check-help.js');

    const created = [];
    const mockDoc = {
      createElement: (tag) => {
        const el = {
          tagName: tag,
          type: '',
          className: '',
          textContent: '',
          title: '',
          attributes: {},
          listeners: {},
          setAttribute(k, v) { this.attributes[k] = String(v); },
          getAttribute(k) { return this.attributes[k] || null; },
          addEventListener(evt, fn) { this.listeners[evt] = fn; },
          focus() { this._focused = true; },
          contains() { return false; },
          appendChild(c) {},
          append(...c) {},
          remove() {},
          getBoundingClientRect() { return { left: 100, top: 100, width: 20, height: 20, bottom: 120, right: 120 }; }
        };
        created.push(el);
        return el;
      },
      querySelectorAll: () => [],
      addEventListener: () => {},
      removeEventListener: () => {},
    };

    const host = mockDoc.createElement('div');
    const btn = createHelpButton(mockDoc, host, 'mode_normal', 'ja');

    console.log(JSON.stringify({
      tagName: btn.tagName,
      className: btn.className,
      textContent: btn.textContent,
      title: btn.title,
      ariaLabel: btn.getAttribute('aria-label'),
      dataHelpTopic: btn.getAttribute('data-help-topic'),
      hasClickListener: typeof btn.listeners['click'] === 'function',
    }));
    """
    res = _run_node(script)
    assert res["tagName"] == "button"
    assert "setup-check-info" in res["className"]
    assert res["textContent"] == "i"
    assert res["dataHelpTopic"] == "mode_normal"
    assert "スキャンモード" in res["title"]
    assert "通常スキャン" in res["ariaLabel"]
    assert "の説明" in res["ariaLabel"]
    assert res["hasClickListener"] is True


def test_attach_help_buttons_auto_wiring():
    """Verify attachHelpButtons scans root and wires buttons to data-help-topic elements without duplicates."""
    script = """
    const { attachHelpButtons } = require('./templates/ui/check-help.js');

    const elementsWithTopic = [];
    function makeElement(tag, topic) {
      const children = [];
      const el = {
        tagName: tag,
        children,
        className: '',
        classList: {
          contains(c) { return el.className.split(' ').includes(c); },
        },
        getAttribute(k) { return k === 'data-help-topic' ? topic : null; },
        querySelector(sel) {
          if (sel === '.setup-check-info') {
            return children.find(c => c.className.includes('setup-check-info')) || null;
          }
          return null;
        },
        appendChild(c) { children.push(c); },
        getBoundingClientRect() { return { left: 0, top: 0, width: 50, height: 20, bottom: 20, right: 50 }; },
      };
      return el;
    }

    const el1 = makeElement('span', 'preflight_gate');
    const el2 = makeElement('div', 'auth_login_verification');
    const root = {
      querySelectorAll(sel) {
        if (sel === '[data-help-topic]') return [el1, el2];
        return [];
      },
      ownerDocument: {
        createElement: (tag) => ({
          tagName: tag,
          className: 'setup-check-info',
          textContent: 'i',
          setAttribute() {},
          getAttribute() {},
          addEventListener() {},
          getBoundingClientRect() { return { left: 0, top: 0, width: 20, height: 20, bottom: 20, right: 20 }; },
        }),
        querySelectorAll: () => [],
        addEventListener: () => {},
        removeEventListener: () => {},
      }
    };

    const firstRun = attachHelpButtons(root, null, 'ja');
    const secondRun = attachHelpButtons(root, null, 'ja');

    console.log(JSON.stringify({
      firstCount: firstRun.length,
      secondCount: secondRun.length,
      el1ChildCount: el1.children.length,
      el2ChildCount: el2.children.length,
    }));
    """
    res = _run_node(script)
    assert res["firstCount"] == 2
    assert res["secondCount"] == 0  # No duplicates
    assert res["el1ChildCount"] == 1
    assert res["el2ChildCount"] == 1


def test_create_button_backwards_compatibility():
    """Verify existing createButton for scanner checks remains functional."""
    script = """
    const { createButton } = require('./templates/ui/check-help.js');

    const mockDoc = {
      createElement: (tag) => ({
        tagName: tag,
        className: '',
        attributes: {},
        setAttribute(k, v) { this.attributes[k] = String(v); },
        getAttribute(k) { return this.attributes[k] || null; },
        addEventListener() {},
        getBoundingClientRect() { return { left: 0, top: 0, width: 20, height: 20, bottom: 20, right: 20 }; },
      }),
      querySelectorAll: () => [],
      addEventListener: () => {},
      removeEventListener: () => {},
    };

    const catalog = {
      sqli: {
        title: 'SQL Injection',
        short_description: 'SQL injection detection',
        what_is_tested: 'Injected sql probes',
        risk_if_vulnerable: 'Database breach',
      }
    };

    const btn = createButton(mockDoc, {}, 'sqli', catalog, 'ja');
    console.log(JSON.stringify({
      className: btn.className,
      textContent: btn.textContent,
      title: btn.title,
    }));
    """
    res = _run_node(script)
    assert res["className"] == "setup-check-info"
    assert res["textContent"] == "i"
    assert res["title"] == "SQL injection detection"
