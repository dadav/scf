"""
Tests for the scf module
"""
from scf.suse import get_all_cve, get_cve_details


def test_suse_submodule():
    """
    Test if the methods of the suse submodule work
    """
    all_cve = get_all_cve()
    assert len(all_cve) > 0
    details = get_cve_details(all_cve[0])
    assert details.name == all_cve[0]
