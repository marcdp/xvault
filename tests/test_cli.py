import pytest

from xvault import __main__ as cli


class FakeVault:
    def __init__(self, path, password=None, no_cache_key=False):
        self.path = path
        self.password = password
        self.no_cache_key = no_cache_key

    @staticmethod
    def is_locked_file(path):
        return False

    @staticmethod
    def is_uninitialized_file(path):
        return False

    def get(self, key, resolve=False):
        if key == "MISSING":
            return None
        return "VALUE123"

    def export(self, resolve=False):
        return "EXPORTED_TEXT"

    def info(self):
        return {
            "File": self.path,
            "Format": "env",
            "Status": "unlocked",
            "Schema version": 1,
            "Crypto version": 1,
            "Encrypted": 0,
        }

    def lock(self):
        return None

    def unlock(self):
        return None

    def rekey(self, new_password):
        return None

    def upgrade(self, password):
        return None

    def set(self, key, value, encrypt=True):
        return None

    def validate(self):
        return {
            "checks": [
                {"name": "parse", "severity": "info", "message": "ok"},
                {"name": "salt", "severity": "info", "message": "ok"},
            ],
            "status": "ok",
        }

    def edit(self):
        return None

    def edit_secret(self, key):
        return None


@pytest.fixture
def patch_exists(monkeypatch):
    monkeypatch.setattr(cli.os.path, "exists", lambda p: True)


@pytest.fixture
def patch_vault(monkeypatch):
    monkeypatch.setattr(cli, "XVault", FakeVault)


def test_version_command_prints_version(capsys):
    cli.versioncmd()
    out = capsys.readouterr()
    assert "xvault " in out.out


def test_get_prints_value(patch_exists, patch_vault, capsys):
    rc = cli.get("any.env", "KEY")
    out = capsys.readouterr()
    assert rc is None
    assert "VALUE123" in out.out


def test_get_missing_key_returns_minus_one(patch_exists, patch_vault, capsys):
    rc = cli.get("any.env", "MISSING")
    out = capsys.readouterr()
    assert rc == -1
    assert "not found" in out.err


def test_get_missing_file_returns_minus_one(monkeypatch, capsys):
    monkeypatch.setattr(cli.os.path, "exists", lambda p: False)
    rc = cli.get("missing.env", "KEY")
    out = capsys.readouterr()
    assert rc == -1
    assert "not found" in out.err


def test_export_prints_text(patch_exists, patch_vault, capsys):
    rc = cli.export("any.env")
    out = capsys.readouterr()
    assert rc is None
    assert "EXPORTED_TEXT" in out.out


def test_info_prints_table(patch_exists, patch_vault, capsys):
    rc = cli.info("any.env")
    out = capsys.readouterr()
    assert rc is None
    assert "File info:" in out.out
    assert "Format" in out.out


def test_lock_when_already_locked_returns_minus_one(monkeypatch, capsys):
    class LockedFakeVault(FakeVault):
        @staticmethod
        def is_locked_file(path):
            return True

        @staticmethod
        def is_uninitialized_file(path):
            return False

    monkeypatch.setattr(cli.os.path, "exists", lambda p: True)
    monkeypatch.setattr(cli, "XVault", LockedFakeVault)
    rc = cli.lock("any.env")
    out = capsys.readouterr()
    assert rc == -1
    assert "already locked" in out.err


def test_unlock_when_not_locked_returns_minus_one(monkeypatch, capsys):
    class UnlockedFakeVault(FakeVault):
        @staticmethod
        def is_locked_file(path):
            return False

    monkeypatch.setattr(cli.os.path, "exists", lambda p: True)
    monkeypatch.setattr(cli, "XVault", UnlockedFakeVault)
    rc = cli.unlock("any.env")
    out = capsys.readouterr()
    assert rc == -1
    assert "is not locked" in out.err


def test_unlock_locked_file_asks_password(monkeypatch, capsys):
    class LockedFakeVault(FakeVault):
        @staticmethod
        def is_locked_file(path):
            return True

    monkeypatch.setattr(cli.os.path, "exists", lambda p: True)
    monkeypatch.setattr(cli, "XVault", LockedFakeVault)
    monkeypatch.setattr(cli, "ask_password", lambda **kwargs: "secret")
    rc = cli.unlock("any.env")
    out = capsys.readouterr()
    assert rc is None
    assert "unlocked" in out.out


def test_validate_prints_checks(patch_exists, patch_vault, capsys):
    rc = cli.validate("any.env")
    out = capsys.readouterr()
    assert rc is None
    assert "- parse" in out.out
    assert "Status: ok" in out.out


def test_validate_reports_malformed_metadata_from_parse_probe(
    monkeypatch, patch_exists, capsys
):
    class MalformedVault(FakeVault):
        @staticmethod
        def is_locked_file(path):
            raise ValueError("Unable to load vault meta: invalid _xvault format")

    monkeypatch.setattr(cli, "XVault", MalformedVault)

    assert cli.validate("any.env") == -1
    output = capsys.readouterr()
    assert "Unable to load vault meta:" in output.err


def test_set_does_not_echo_secret(patch_exists, patch_vault, capsys):
    secret = "do-not-echo-this"

    rc = cli.set("any.env", "DB_PASS", secret)

    out = capsys.readouterr()
    assert rc is None
    assert out.out == "Key 'DB_PASS' updated.\n"
    assert secret not in out.out
    assert secret not in out.err


def test_set_no_encrypt_is_forwarded(monkeypatch, patch_exists):
    calls = []

    class RecordingVault(FakeVault):
        def set(self, key, value, encrypt=True):
            calls.append((key, value, encrypt))

    monkeypatch.setattr(cli, "XVault", RecordingVault)

    cli.set("any.env", "PUBLIC", "plain-value", no_encrypt=True)

    assert calls == [("PUBLIC", "plain-value", False)]


@pytest.mark.parametrize(
    ("status", "expected"),
    [("warning", None), ("error", -1)],
)
def test_validate_exit_policy(monkeypatch, patch_exists, capsys, status, expected):
    class StatusVault(FakeVault):
        def validate(self):
            return {
                "checks": [{"name": "status", "severity": status, "message": status}],
                "status": status,
            }

    monkeypatch.setattr(cli, "XVault", StatusVault)

    assert cli.validate("any.env") == expected


def test_main_propagates_command_failure(monkeypatch):
    class FailingCommandsManager:
        def register(self, module):
            pass

        def execute(self, argv, default_show_help=True):
            return -1

    monkeypatch.setattr(cli, "CommandsManager", FailingCommandsManager)

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 1


def test_rekey_asks_new_password(monkeypatch):
    calls = []

    class RekeyFakeVault(FakeVault):
        @staticmethod
        def is_locked_file(path):
            return False

        @staticmethod
        def is_uninitialized_file(path):
            return False

        def rekey(self, new_password):
            calls.append(new_password)

    monkeypatch.setattr(cli.os.path, "exists", lambda p: True)
    monkeypatch.setattr(cli, "XVault", RekeyFakeVault)
    monkeypatch.setattr(
        cli,
        "ask_password",
        lambda **kwargs: "new-secret" if kwargs.get("confirm") else "old-secret",
    )

    rc = cli.rekey("any.env")
    assert rc is None
    assert calls == ["new-secret"]


def test_upgrade_requires_password_again(monkeypatch, capsys):
    calls = []

    class UpgradeFakeVault(FakeVault):
        def upgrade(self, password):
            calls.append(password)

    monkeypatch.setattr(cli.os.path, "exists", lambda p: True)
    monkeypatch.setattr(cli, "XVault", UpgradeFakeVault)
    monkeypatch.setattr(cli, "ask_password", lambda **kwargs: "migration-password")

    assert cli.upgrade("any.env") is None
    assert calls == ["migration-password"]
    assert "upgraded" in capsys.readouterr().out


def test_edit_calls_edit_secret_when_key_is_provided(monkeypatch):
    calls = []

    class EditFakeVault(FakeVault):
        def edit_secret(self, key):
            calls.append(("edit_secret", key))

        def edit(self):
            calls.append(("edit", None))

    monkeypatch.setattr(cli.os.path, "exists", lambda p: True)
    monkeypatch.setattr(cli, "XVault", EditFakeVault)

    rc = cli.edit("any.env", key="DB_PASS")
    assert rc is None
    assert calls == [("edit_secret", "DB_PASS")]


def test_edit_calls_edit_when_key_is_not_provided(monkeypatch):
    calls = []

    class EditFakeVault(FakeVault):
        def edit_secret(self, key):
            calls.append(("edit_secret", key))

        def edit(self):
            calls.append(("edit", None))

    monkeypatch.setattr(cli.os.path, "exists", lambda p: True)
    monkeypatch.setattr(cli, "XVault", EditFakeVault)

    rc = cli.edit("any.env")
    assert rc is None
    assert calls == [("edit", None)]
