"""Normalizer test: captured nmap XML -> services + findings, no Docker or nmap required."""
from runtime.normalize.nmap import parse_nmap_xml

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parses_open_ports_only():
    out = parse_nmap_xml(SAMPLE_XML, engagement_id="e1", run_id="r1", target="10.0.0.5")
    # The closed 443 port is dropped; only the two open ports become services.
    assert {s.port for s in out.services} == {22, 80}
    assert len(out.findings) == 2


def test_findings_carry_topology_and_dedup():
    out = parse_nmap_xml(SAMPLE_XML, engagement_id="e1", run_id="r1", target="10.0.0.5")
    ssh = next(f for f in out.findings if "22" in f.title)
    assert ssh.category == "open-port"
    assert ssh.target == "10.0.0.5"
    assert ssh.source_tool == "nmap"
    # dedup key is stable for the same issue on the same host.
    assert ssh.dedup_key() == "e1|open-port|10.0.0.5|"
