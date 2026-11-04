from pathlib import Path
import sys

import pytest
from keyring.errors import PasswordDeleteError


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(autouse=True)
def fake_keyring(monkeypatch):
    """Use an in-memory keyring for tests to avoid OS keyring dependencies."""
    store = {}

    def set_password(service_name, username, password):
        store[(service_name, username)] = password

    def get_password(service_name, username):
        return store.get((service_name, username))

    def delete_password(service_name, username):
        key = (service_name, username)
        if key not in store:
            raise PasswordDeleteError("not found")
        del store[key]

    monkeypatch.setattr("keyring.set_password", set_password)
    monkeypatch.setattr("keyring.get_password", get_password)
    monkeypatch.setattr("keyring.delete_password", delete_password)
