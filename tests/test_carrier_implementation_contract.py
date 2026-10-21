"""宣言と canonical 注入経路の実装をブラウザ・送信なしで照合する。"""
from dataclasses import replace

import pytest

from wscan.injection_point import InjectionPoint
from wscan.scanner_contract import (
    CapabilityState, Carrier, PayloadShape, validate_carrier_implementation,
    validate_scanner_contract,
)
from wscan.scanners import SCANNERS


_POINTS = {
    Carrier.QUERY: InjectionPoint.for_url_param("http://fixture.test/", "q"),
    Carrier.FORM: InjectionPoint.for_form("http://fixture.test/", "q"),
    Carrier.JSON: InjectionPoint.for_json_body("POST", "http://fixture.test/", "/q"),
}
_CANONICAL = frozenset(_POINTS)

# scan_page/scan_field の独自送信経路。facade 統合時は該当項目を削除する。
_CUSTOM_TRANSPORTS = {
    "privesc": frozenset({Carrier.QUERY, Carrier.FORM}),
    "stored_xss": frozenset({Carrier.QUERY, Carrier.FORM}),
    "race_condition": frozenset({Carrier.FORM}),
    "prototype_pollution": frozenset({Carrier.QUERY, Carrier.JSON}),
    "mass_assignment": frozenset({Carrier.JSON}),
}


def _facade_carriers(cls):
    scanner = cls.__new__(cls)
    return frozenset(
        carrier for carrier, ip in _POINTS.items()
        # override 検出だけでは DOM-XSS の JSON まで True になるため JSON flag も照合。
        if (carrier != Carrier.JSON or cls.SUPPORTS_JSON_BODY)
        and scanner._dispatch_driver_available(ip)
    )


@pytest.mark.parametrize("check,cls", SCANNERS.items())
def test_canonical_carrier_declarations_match_implementation(check, cls):
    drivers = _facade_carriers(cls)
    custom = _CUSTOM_TRANSPORTS.get(check, frozenset())
    assert not drivers & custom, f"{check}: facade 統合済みの custom transport 記録を削除する"
    assert not validate_carrier_implementation(
        check, cls.CONTRACT, drivers | custom, carrier_scope=_CANONICAL,
    )
    assert not validate_scanner_contract(check, cls.CONTRACT)
    for cap in cls.CONTRACT.capabilities:
        if cap.state == CapabilityState.SUPPORTED:
            assert cap.structured_payload == (PayloadShape.STRUCTURED in cap.payload_shapes)


def test_custom_transport_registry_has_no_unknown_scanners():
    assert _CUSTOM_TRANSPORTS.keys() <= SCANNERS.keys()


@pytest.mark.parametrize("declared,implemented", [(False, True), (True, False), (True, True)])
def test_carrier_validation_rejects_drift_and_accepts_matching_twin(declared, implemented):
    contract = SCANNERS["sqli"].CONTRACT
    query = contract.capability(Carrier.QUERY)
    contract = replace(contract, capabilities=(replace(
        query, state=CapabilityState.SUPPORTED if declared else CapabilityState.UNSUPPORTED,
    ),))
    errors = validate_carrier_implementation(
        "fixture", contract, frozenset({Carrier.QUERY}) if implemented else frozenset(),
        carrier_scope=frozenset({Carrier.QUERY}),
    )
    assert bool(errors) == (declared != implemented)
    if errors:
        assert errors[0].startswith("fixture:query:")


def test_carrier_validation_checks_all_carriers_by_default():
    contract = SCANNERS["graphql"].CONTRACT
    assert not validate_carrier_implementation("graphql", contract, frozenset({Carrier.GRAPHQL}))
    assert validate_carrier_implementation("graphql", contract, frozenset()) == [
        "graphql:graphql: declared supported but no implementation",
    ]
