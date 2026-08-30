"""The service/time/firewall reducer — six facts the baselines ask for and
nothing wrote.

A real compliance scan on 2026-08-30 reported "16 of 20 rules could not be
evaluated", each naming the fact it wanted: `no collector writes
host.ntp_enabled`, `host.ssh_running`, `host.firewall_enabled`, and so on. The
baselines already declare where each comes from — vocabulary.py names
`HostServiceSystem.serviceInfo.service[ntpd].running` and its siblings — so what
was missing was the collector, not the design.

Six of those sixteen come from one batched PropertyCollector pass. This is the
pure reducer over its result; the fetch wrapper around it is real-hardware-gated
like `_fetch_advanced_settings`.

The rule that shapes every case below: **a service that is not present is not a
service that is off.** ESXi reports the services it has; a build without ntpd
(some use chrony, some ship a trimmed image) simply omits it. Writing
`ntp_enabled: false` there would report a compliance failure for a fact nobody
measured, which is the defect vmware-harden v1.9.0 was released to remove.
Absent stays absent, and a rule with no value is "not evaluated".
"""

from __future__ import annotations

import types

from vmware_harden.collectors.hosts import _service_and_time_attrs


def _svc(key, running, policy):
    return types.SimpleNamespace(key=key, running=running, policy=policy)


def _props(services=(), ntp_servers=None, firewall_policy=None):
    return {
        "config.service": types.SimpleNamespace(service=list(services)),
        "config.dateTimeInfo": (
            types.SimpleNamespace(ntpConfig=types.SimpleNamespace(server=ntp_servers))
            if ntp_servers is not None else None
        ),
        "config.firewall": (
            types.SimpleNamespace(defaultPolicy=firewall_policy)
            if firewall_policy is not None else None
        ),
    }


class TestNtp:
    def test_running_ntpd_is_enabled(self):
        a = _service_and_time_attrs(_props([_svc("ntpd", True, "on")]))
        assert a["ntp_enabled"] is True
        assert a["ntp_service_policy_on"] is True

    def test_stopped_ntpd_is_reported_stopped_not_absent(self):
        a = _service_and_time_attrs(_props([_svc("ntpd", False, "off")]))
        assert a["ntp_enabled"] is False
        assert a["ntp_service_policy_on"] is False

    def test_a_policy_of_automatic_counts_as_on(self):
        """ESXi policy is on / off / automatic. `automatic` starts the service
        with its firewall port, so it is not 'off'."""
        a = _service_and_time_attrs(_props([_svc("ntpd", True, "automatic")]))
        assert a["ntp_service_policy_on"] is True

    def test_an_absent_ntpd_writes_nothing(self):
        """Not every build ships ntpd. Absent must not become False — that
        would report a violation for a fact nobody measured."""
        a = _service_and_time_attrs(_props([_svc("TSM-SSH", True, "on")]))
        assert "ntp_enabled" not in a
        assert "ntp_service_policy_on" not in a

    def test_servers_are_listed_when_configured(self):
        a = _service_and_time_attrs(_props(ntp_servers=["10.0.0.1", "10.0.0.2"]))
        assert a["ntp_servers"] == ["10.0.0.1", "10.0.0.2"]

    def test_configured_with_no_servers_is_an_empty_list_not_absent(self):
        """Here empty IS the measurement: time sync is configured with nothing
        to sync to, which a baseline should be able to fail on."""
        a = _service_and_time_attrs(_props(ntp_servers=[]))
        assert a["ntp_servers"] == []

    def test_unreadable_time_config_writes_nothing(self):
        assert "ntp_servers" not in _service_and_time_attrs(_props())


class TestSsh:
    def test_running_and_policy_are_separate_facts(self):
        a = _service_and_time_attrs(_props([_svc("TSM-SSH", True, "off")]))
        assert a["ssh_running"] is True
        assert a["ssh_enabled"] is False, "policy 'off' is not the same as not running"

    def test_absent_ssh_service_writes_nothing(self):
        a = _service_and_time_attrs(_props([_svc("ntpd", True, "on")]))
        assert "ssh_running" not in a and "ssh_enabled" not in a


class TestFirewall:
    def test_blocked_incoming_is_enabled(self):
        pol = types.SimpleNamespace(incomingBlocked=True, outgoingBlocked=True)
        assert _service_and_time_attrs(_props(firewall_policy=pol))["firewall_enabled"] is True

    def test_open_incoming_is_not_enabled(self):
        pol = types.SimpleNamespace(incomingBlocked=False, outgoingBlocked=False)
        assert _service_and_time_attrs(_props(firewall_policy=pol))["firewall_enabled"] is False

    def test_unreadable_firewall_writes_nothing(self):
        assert "firewall_enabled" not in _service_and_time_attrs(_props())


def test_a_host_that_answers_nothing_yields_no_attrs():
    """The whole point. An unreadable host must produce zero facts, so every
    rule over it reports 'not evaluated' rather than a passing or failing
    verdict nobody measured."""
    assert _service_and_time_attrs({}) == {}
