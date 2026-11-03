"""Tests for Monitor pane layout pure functions, validation, and persistence."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
MONITOR_MODULE_JS = ROOT / "templates" / "ui" / "monitor-module.js"


def _run_node(script: str) -> dict:
    """Execute snippet with monitor module in Node.js via stdin and return parsed JSON."""
    res = subprocess.run(
        ["node", "-"],
        input=script,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(res.stdout)


def test_default_layout_and_presets():
    script = """
    const mod = require('./templates/ui/monitor-module.js');
    console.log(JSON.stringify({
        defaultLayout: mod.DEFAULT_LAYOUT,
        presets: mod.PRESETS,
        bounds: mod.LAYOUT_BOUNDS,
        storageKey: mod.STORAGE_KEY,
    }));
    """
    res = _run_node(script)
    dl = res["defaultLayout"]
    assert dl["version"] == 1
    assert dl["preset"] == "standard"
    assert dl["leftWidth"] == 320
    assert dl["rightWidth"] == 300
    assert dl["collapsed"] == {"left": False, "center": False, "right": False}
    assert dl["maximized"] is None

    presets = res["presets"]
    assert set(presets.keys()) == {"standard", "browser-focused", "log-focused"}
    assert presets["standard"]["preset"] == "standard"
    assert presets["browser-focused"]["preset"] == "browser-focused"
    assert presets["browser-focused"]["collapsed"]["left"] is True
    assert presets["log-focused"]["preset"] == "log-focused"
    assert presets["log-focused"]["collapsed"]["right"] is True
    assert presets["log-focused"]["leftWidth"] >= 500

    bounds = res["bounds"]
    assert bounds["left"]["min"] == 160
    assert bounds["right"]["min"] == 160
    assert bounds["minCenter"] == 200
    assert res["storageKey"] == "vulix:monitor-layout:v1"


def test_preference_validation_and_parsing_with_clean_data():
    script = """
    const mod = require('./templates/ui/monitor-module.js');
    const valid = {
        version: 1,
        preset: 'browser-focused',
        leftWidth: 220,
        rightWidth: 280,
        collapsed: { left: true, center: false, right: false },
        maximized: null
    };
    const parsed = mod.parseLayoutPreferences(JSON.stringify(valid));
    console.log(JSON.stringify({ parsed }));
    """
    res = _run_node(script)
    p = res["parsed"]
    assert p["version"] == 1
    assert p["preset"] == "browser-focused"
    assert p["leftWidth"] == 220
    assert p["rightWidth"] == 280
    assert p["collapsed"] == {"left": True, "center": False, "right": False}
    assert p["maximized"] is None


def test_preference_parsing_rejects_corrupt_and_old_version():
    script = """
    const mod = require('./templates/ui/monitor-module.js');
    const results = {
        nullInput: mod.parseLayoutPreferences(null),
        emptyInput: mod.parseLayoutPreferences(''),
        corruptJson: mod.parseLayoutPreferences('{broken json'),
        notObject: mod.parseLayoutPreferences('[1, 2, 3]'),
        oldVersion: mod.parseLayoutPreferences(JSON.stringify({
            version: 0,
            preset: 'standard',
            leftWidth: 320,
            rightWidth: 300,
            collapsed: { left: false, center: false, right: false },
            maximized: null
        })),
        futureVersion: mod.parseLayoutPreferences(JSON.stringify({
            version: 2,
            preset: 'standard',
            leftWidth: 320,
            rightWidth: 300,
            collapsed: { left: false, center: false, right: false },
            maximized: null
        })),
        missingVersion: mod.parseLayoutPreferences(JSON.stringify({
            preset: 'standard',
            leftWidth: 320,
            rightWidth: 300,
            collapsed: { left: false, center: false, right: false },
            maximized: null
        })),
    };
    console.log(JSON.stringify(results));
    """
    res = _run_node(script)
    for key, val in res.items():
        assert val["version"] == 1
        assert val["preset"] == "standard"
        assert val["leftWidth"] == 320
        assert val["rightWidth"] == 300


def test_preference_parsing_rejects_secret_looking_and_url_inputs():
    script = """
    const mod = require('./templates/ui/monitor-module.js');
    const results = {
        withToken: mod.parseLayoutPreferences(JSON.stringify({
            version: 1,
            token: 'secret_abc_123',
            preset: 'standard',
            leftWidth: 320,
            rightWidth: 300,
            collapsed: { left: false, center: false, right: false },
            maximized: null
        })),
        withUrlPreset: mod.parseLayoutPreferences(JSON.stringify({
            version: 1,
            preset: 'https://evil.example.com',
            leftWidth: 320,
            rightWidth: 300,
            collapsed: { left: false, center: false, right: false },
            maximized: null
        })),
        withBearer: mod.parseLayoutPreferences(JSON.stringify({
            version: 1,
            preset: 'standard',
            leftWidth: 320,
            rightWidth: 300,
            collapsed: { left: false, center: false, right: false },
            maximized: null,
            note: 'Bearer secret_value'
        })),
        withScanId: mod.parseLayoutPreferences(JSON.stringify({
            version: 1,
            preset: 'standard',
            leftWidth: 320,
            rightWidth: 300,
            collapsed: { left: false, center: false, right: false },
            maximized: null,
            scanId: 'scan_20261026_000000'
        })),
        withExtraKey: mod.parseLayoutPreferences(JSON.stringify({
            version: 1,
            preset: 'standard',
            leftWidth: 320,
            rightWidth: 300,
            collapsed: { left: false, center: false, right: false },
            maximized: null,
            unknownProp: 42
        })),
        withInvalidTypes: mod.parseLayoutPreferences(JSON.stringify({
            version: 1,
            preset: 'standard',
            leftWidth: 'very wide',
            rightWidth: 300,
            collapsed: { left: false, center: false, right: false },
            maximized: null
        })),
        withNegativeWidth: mod.parseLayoutPreferences(JSON.stringify({
            version: 1,
            preset: 'standard',
            leftWidth: -100,
            rightWidth: 300,
            collapsed: { left: false, center: false, right: false },
            maximized: null
        })),
    };
    console.log(JSON.stringify(results));
    """
    res = _run_node(script)
    for key, val in res.items():
        assert val["version"] == 1
        assert val["preset"] == "standard"
        assert val["leftWidth"] == 320
        assert val["rightWidth"] == 300
        assert "token" not in val
        assert "note" not in val
        assert "scanId" not in val
        assert "unknownProp" not in val


def test_storage_load_and_save_handles_exceptions_and_persists_clean_data():
    script = """
    const mod = require('./templates/ui/monitor-module.js');
    let store = {};
    const mockStorage = {
        getItem: (k) => store[k] || null,
        setItem: (k, v) => { store[k] = v; },
    };

    const throwingStorage = {
        getItem: () => { throw new Error('Quota or security error'); },
        setItem: () => { throw new Error('Quota or security error'); },
    };

    const saved = mod.savePreferences(mockStorage, {
        version: 1,
        preset: 'log-focused',
        leftWidth: 550,
        rightWidth: 260,
        collapsed: { left: false, center: false, right: true },
        maximized: null,
    });

    const loaded = mod.loadPreferences(mockStorage);
    const rawStored = store[mod.STORAGE_KEY];

    const throwLoad = mod.loadPreferences(throwingStorage);
    const throwSave = mod.savePreferences(throwingStorage, loaded);

    console.log(JSON.stringify({
        saved,
        loaded,
        rawStored: JSON.parse(rawStored),
        throwLoad,
        throwSave,
    }));
    """
    res = _run_node(script)
    assert res["saved"] is True
    assert res["loaded"]["preset"] == "log-focused"
    assert res["loaded"]["leftWidth"] == 550
    assert res["loaded"]["collapsed"]["right"] is True

    raw = res["rawStored"]
    assert set(raw.keys()) == {"version", "preset", "leftWidth", "rightWidth", "collapsed", "maximized"}
    assert raw["version"] == 1

    assert res["throwLoad"]["preset"] == "standard"
    assert res["throwSave"] is False


def test_separator_keyboard_handling_and_bounds():
    script = """
    const mod = require('./templates/ui/monitor-module.js');
    const opts = { min: 160, max: 700, step: 20, invert: false };
    const invertOpts = { min: 160, max: 700, step: 20, invert: true };

    const results = {
        leftDecrease: mod.applySeparatorKey(320, 'ArrowLeft', opts),
        leftIncrease: mod.applySeparatorKey(320, 'ArrowRight', opts),
        leftMinClamp: mod.applySeparatorKey(170, 'ArrowLeft', opts),
        leftMinExact: mod.applySeparatorKey(160, 'ArrowLeft', opts),
        leftMaxClamp: mod.applySeparatorKey(690, 'ArrowRight', opts),
        leftHome: mod.applySeparatorKey(320, 'Home', opts),
        leftEnd: mod.applySeparatorKey(320, 'End', opts),
        otherKey: mod.applySeparatorKey(320, 'Enter', opts),

        // Right separator inverted behavior
        rightArrowLeft: mod.applySeparatorKey(300, 'ArrowLeft', invertOpts),
        rightArrowRight: mod.applySeparatorKey(300, 'ArrowRight', invertOpts),
        rightHome: mod.applySeparatorKey(300, 'Home', invertOpts),
        rightEnd: mod.applySeparatorKey(300, 'End', invertOpts),
    };
    console.log(JSON.stringify(results));
    """
    res = _run_node(script)
    assert res["leftDecrease"] == 300
    assert res["leftIncrease"] == 340
    assert res["leftMinClamp"] == 160
    assert res["leftMinExact"] == 160
    assert res["leftMaxClamp"] == 700
    assert res["leftHome"] == 160
    assert res["leftEnd"] == 700
    assert res["otherKey"] == 320

    assert res["rightArrowLeft"] == 320
    assert res["rightArrowRight"] == 280
    assert res["rightHome"] == 160
    assert res["rightEnd"] == 700


def test_preset_application_and_fallbacks():
    script = """
    const mod = require('./templates/ui/monitor-module.js');
    const std = mod.applyPreset('standard');
    const browser = mod.applyPreset('browser-focused');
    const log = mod.applyPreset('log-focused');
    const unknown = mod.applyPreset('non-existent');

    console.log(JSON.stringify({ std, browser, log, unknown }));
    """
    res = _run_node(script)
    assert res["std"]["preset"] == "standard"
    assert res["std"]["leftWidth"] == 320
    assert res["std"]["collapsed"]["left"] is False

    assert res["browser"]["preset"] == "browser-focused"
    assert res["browser"]["collapsed"]["left"] is True

    assert res["log"]["preset"] == "log-focused"
    assert res["log"]["leftWidth"] >= 500
    assert res["log"]["collapsed"]["right"] is True

    assert res["unknown"]["preset"] == "standard"


def test_toggle_collapse_and_maximize_logic():
    script = """
    const mod = require('./templates/ui/monitor-module.js');
    let layout = mod.applyPreset('standard');

    const colLeft = mod.togglePaneCollapse(layout, 'left');
    const expandLeft = mod.togglePaneCollapse(colLeft, 'left');

    // Prevent collapsing all three
    let allCol = mod.togglePaneCollapse(layout, 'left');
    allCol = mod.togglePaneCollapse(allCol, 'center');
    const rejectThirdCol = mod.togglePaneCollapse(allCol, 'right');

    // Maximize left
    const maxLeft = mod.togglePaneMaximize(layout, 'left');
    const restoreLeft = mod.togglePaneMaximize(maxLeft, 'left');

    console.log(JSON.stringify({
        colLeft: colLeft.collapsed,
        expandLeft: expandLeft.collapsed,
        rejectThirdCol: rejectThirdCol.collapsed,
        maxLeft: maxLeft.maximized,
        restoreLeft: restoreLeft.maximized,
    }));
    """
    res = _run_node(script)
    assert res["colLeft"]["left"] is True
    assert res["expandLeft"]["left"] is False
    assert res["rejectThirdCol"]["right"] is False
    assert res["maxLeft"] == "left"
    assert res["restoreLeft"] is None


def test_compute_pane_dimensions():
    script = """
    const mod = require('./templates/ui/monitor-module.js');
    const stdDims = mod.computePaneDimensions(mod.PRESETS['standard'], 1200);
    const colDims = mod.computePaneDimensions({
        version: 1,
        preset: 'custom',
        leftWidth: 320,
        rightWidth: 300,
        collapsed: { left: true, center: false, right: false },
        maximized: null
    }, 1200);
    const maxDims = mod.computePaneDimensions({
        version: 1,
        preset: 'custom',
        leftWidth: 320,
        rightWidth: 300,
        collapsed: { left: false, center: false, right: false },
        maximized: 'center'
    }, 1200);

    console.log(JSON.stringify({ stdDims, colDims, maxDims }));
    """
    res = _run_node(script)
    s = res["stdDims"]
    assert s["left"]["width"] == 320
    assert s["right"]["width"] == 300
    assert s["center"]["flex"] == 1
    assert s["sepLeft"]["visible"] is True
    assert s["sepRight"]["visible"] is True

    c = res["colDims"]
    assert c["left"]["width"] == 36
    assert c["left"]["collapsed"] is True
    assert c["sepLeft"]["visible"] is False

    m = res["maxDims"]
    assert m["center"]["maximized"] is True
    assert m["left"]["visible"] is False
    assert m["right"]["visible"] is False
    assert m["sepLeft"]["visible"] is False
    assert m["sepRight"]["visible"] is False
