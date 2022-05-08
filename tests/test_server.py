"""
Tests for the api server
"""
import pytest
import requests
from scf.server import app
from fastapi.testclient import TestClient


client = TestClient(app)


def test_docs():
    """
    Test if the docs are reachable
    """
    response = client.get('/')
    assert response.status_code == 200
    response = client.get('/redoc')
    assert response.status_code == 200


def test_cve():
    """
    Test if the cve api call works
    """
    # valid
    response = client.get('/cve/CVE-2022-0001')
    assert response.status_code == 200
    # invalid
    with pytest.raises(requests.exceptions.HTTPError) as err:
        response = client.get('/cve/invalid')
        assert '404' in str(err.value)
