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


# --- B2: a range scan's XML describes many <host> elements in one document. Each must be attributed
# to its own address, not collapsed onto the run's seed target (which for a range is the CIDR itself,
# not any one host).
MULTI_HOST_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.0.0.9" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_multi_host_xml_attributes_each_service_to_its_own_address():
    out = parse_nmap_xml(MULTI_HOST_XML, engagement_id="e1", run_id="r1", target="10.0.0.0/24")
    addresses = {s.address for s in out.services}
    assert addresses == {"10.0.0.5", "10.0.0.9"}
    assert {f.target for f in out.findings} == {"10.0.0.5", "10.0.0.9"}


# --- B2: a pure host-discovery sweep (`-sn`) never scans a port, so services/findings are always
# empty. Without surfacing which hosts answered "up", that would be indistinguishable from a sweep
# that found nothing -- exactly the ambiguity the agent's range guidance tells it to treat as "stop".
SWEEP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.6" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.0.0.9" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def test_sweep_with_no_ports_surfaces_up_hosts_as_a_note():
    out = parse_nmap_xml(SWEEP_XML, engagement_id="e1", run_id="r1", target="10.0.0.0/24")
    assert out.services == []
    assert out.findings == []
    assert "10.0.0.5" in out.note and "10.0.0.9" in out.note
    assert "10.0.0.6" not in out.note  # down hosts are not reported as up
    assert out.note.startswith("2 host(s) up")


def test_sweep_with_no_hosts_up_produces_an_empty_note():
    empty = """<?xml version="1.0"?><nmaprun></nmaprun>"""
    out = parse_nmap_xml(empty, engagement_id="e1", run_id="r1", target="10.0.0.0/24")
    assert out.services == [] and out.findings == [] and out.note == ""
