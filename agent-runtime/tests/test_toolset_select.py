"""Per-run tool selection (the "tool library" checkboxes) narrows the planner's registry."""
from runtime.toolset import all_tools, select_tools


class _T:
    def __init__(self, name):
        self.name = name


def test_none_or_empty_selection_means_all():
    tools = [_T("nmap"), _T("nuclei"), _T("semgrep")]
    assert [t.name for t in select_tools(tools, None)] == ["nmap", "nuclei", "semgrep"]
    assert [t.name for t in select_tools(tools, [])] == ["nmap", "nuclei", "semgrep"]


def test_selection_filters_to_chosen_tools_only():
    tools = [_T("nmap"), _T("nuclei"), _T("semgrep")]
    chosen = select_tools(tools, ["nmap", "semgrep"])
    assert [t.name for t in chosen] == ["nmap", "semgrep"]  # nuclei is excluded -> cannot be planned


def test_unknown_names_are_ignored():
    tools = [_T("nmap"), _T("semgrep")]
    assert [t.name for t in select_tools(tools, ["nmap", "does-not-exist"])] == ["nmap"]


def test_empty_match_falls_back_to_all_not_a_toolless_run():
    tools = [_T("nmap"), _T("semgrep")]
    # A selection that matches nothing (all stale) must not yield a run with zero tools.
    assert [t.name for t in select_tools(tools, ["ghost"])] == ["nmap", "semgrep"]


def test_selection_works_over_the_real_registry():
    tools = all_tools()
    names = {t.name for t in tools}
    assert "nmap" in names and "semgrep" in names
    chosen = {t.name for t in select_tools(tools, ["nmap"])}
    assert chosen == {"nmap"}
