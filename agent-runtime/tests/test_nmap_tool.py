"""B2: NmapTool.build_command must not run a single-host-shaped scan against a whole range.

A range target used to keep -Pn (skip host discovery, scan every address as if up) plus the
single-host flag table (--top-ports 1000 or -p-) verbatim -- against a /24 that's 256 full port
scans in one call, which is enormous or times out and teaches the agent nothing before its
tool-call budget (or the sandbox timeout) is spent. These tests pin the new range-vs-single-host
branch: single hosts are byte-for-byte unchanged, ranges get a cheap sweep, and an oversized range
is refused with a clear, budget-preserving error rather than silently truncated or left to run
forever.
"""
import pytest
from app.models import Intensity

from runtime.tools.nmap import NmapTool


def test_single_host_keeps_pn_and_the_existing_flag_table():
    tool = NmapTool()
    for intensity in Intensity:
        cmd = tool.build_command("10.0.0.5", intensity)
        assert cmd[0] == "-Pn"
        assert "-oX" in cmd and cmd[-1] == "10.0.0.5"


def test_hostname_target_is_treated_as_a_single_host():
    # Not parseable as an ip_network -> always the single-host path, same as before.
    tool = NmapTool()
    cmd = tool.build_command("example.com", Intensity.normal)
    assert cmd[0] == "-Pn"


@pytest.mark.parametrize("intensity", [Intensity.passive, Intensity.light])
def test_range_at_quiet_intensity_is_a_pure_discovery_sweep(intensity):
    tool = NmapTool()
    cmd = tool.build_command("10.0.0.0/24", intensity)
    assert "-Pn" not in cmd  # dropped for ranges -- see module docstring
    assert "-sn" in cmd
    assert cmd[-1] == "10.0.0.0/24"


@pytest.mark.parametrize("intensity", [Intensity.normal, Intensity.aggressive])
def test_range_at_higher_intensity_is_a_narrow_top_ports_scan(intensity):
    tool = NmapTool()
    cmd = tool.build_command("10.0.0.0/24", intensity)
    assert "-Pn" not in cmd
    assert "-sn" not in cmd
    assert "--top-ports" in cmd and "100" in cmd
    # Never the single-host table's --top-ports 1000 / -p- for a whole range.
    assert "1000" not in cmd and "-p-" not in cmd


def test_slash_32_target_is_a_single_host_not_a_range():
    tool = NmapTool()
    cmd = tool.build_command("10.0.0.5/32", Intensity.light)
    assert cmd[0] == "-Pn"  # single-host path, not the sweep


def test_oversized_range_is_refused_with_a_clear_error():
    tool = NmapTool()
    # A /21 is 2048 addresses -- over the 1024 default cap.
    with pytest.raises(ValueError, match=r"range too large \(2048 addresses\); scan a smaller prefix"):
        tool.build_command("10.0.0.0/21", Intensity.light)


def test_max_sweep_hosts_env_raises_the_cap():
    tool = NmapTool()
    # A /21 is 2048 addresses -- refused under the 1024 default.
    with pytest.raises(ValueError, match="range too large"):
        tool.build_command("10.0.0.0/21", Intensity.light)


def test_max_sweep_hosts_env_is_honored(monkeypatch):
    monkeypatch.setenv("EYE_MAX_SWEEP_HOSTS", "4096")
    tool = NmapTool()
    # The same /21 that's refused by default is allowed once the cap is raised past 2048.
    cmd = tool.build_command("10.0.0.0/21", Intensity.light)
    assert "-sn" in cmd


def test_max_sweep_hosts_env_still_refuses_above_the_configured_cap(monkeypatch):
    monkeypatch.setenv("EYE_MAX_SWEEP_HOSTS", "100")
    tool = NmapTool()
    with pytest.raises(ValueError, match="range too large"):
        tool.build_command("10.0.0.0/24", Intensity.light)  # 256 > 100
