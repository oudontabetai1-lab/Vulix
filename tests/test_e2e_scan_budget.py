"""E2E の時間切れを recall 低下と区別する診断。"""
import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from tests.test_end_to_end_scan import _run_measured_scan


def test_scan_timeout_is_not_a_recall_failure(capsys):
    async def run():
        await asyncio.sleep(1)

    engine = SimpleNamespace(scanners={}, run=run)
    with patch('tests.test_end_to_end_scan.SCAN_TIMEOUT_S', 0.001):
        with pytest.raises(RuntimeError, match='SCAN TIMEOUT:.*recall NOT EVALUATED'):
            asyncio.run(_run_measured_scan(engine))
    assert 'SCAN elapsed=' in capsys.readouterr().err


def test_completed_scan_preserves_results_and_reports_check_time(capsys):
    async def scan(value):
        return value

    scanner = SimpleNamespace(scan_injection_point=scan)

    async def run():
        assert await scanner.scan_injection_point('finding') == 'finding'

    asyncio.run(_run_measured_scan(SimpleNamespace(scanners={'xss': scanner}, run=run)))
    assert "'xss':" in capsys.readouterr().err
