from pathlib import Path
import subprocess
import re
import duckdb
import json
import tempfile
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parent.parent
ENVIRONMENT = ROOT / "environment"

EXPECTED_REPORT = (
    ENVIRONMENT
    / "reports"
    / "publications.expected.txt"
)
CURRENT_CERT = ENVIRONMENT / "keys" / "current" / "current.cert.pem"
CURRENT_KEY = ENVIRONMENT / "keys" / "current" / "current.key.pem"

REVOKED_CERT = ENVIRONMENT / "keys" / "revoked" / "revoked.cert.pem"
REVOKED_KEY = ENVIRONMENT / "keys" / "revoked" / "revoked.key.pem"


def test_expected_report_exists():
    assert EXPECTED_REPORT.exists(), (
        f"Expected golden report not found: {EXPECTED_REPORT}"
    )


def test_expected_report_is_not_empty():
    content = EXPECTED_REPORT.read_text().strip()

    assert content, "Expected golden report must not be empty"


def test_expected_report_has_publication_lines():
    content = EXPECTED_REPORT.read_text()

    assert "BUNDLE" in content
    assert "SIGNED KEY=" in content
    assert "PUBLISHED RECEIPT=" in content
    assert "STATUS=PUBLISHED" in content

def test_publisher_runs():
    result = subprocess.run(
        ["npm.cmd", "run", "report"],
        cwd=ENVIRONMENT,
        capture_output=True,
        text=True
    )

    assert result.returncode == 0, (
        f"Publisher failed:\n{result.stdout}\n{result.stderr}"
    )

def test_reconciliation_output():
    result = subprocess.run(
        ["npm.cmd", "run", "report"],
        cwd=ENVIRONMENT,
        capture_output=True,
        text=True
    )

    assert result.returncode == 0

    output = result.stdout

    assert "BUNDLE BND-101" in output
    assert "BUNDLE BND-102" in output
    assert "BUNDLE BND-103" in output

def test_publisher_is_idempotent():
    first_run = subprocess.run(
        ["npm.cmd", "run", "report"],
        cwd=ENVIRONMENT,
        capture_output=True,
        text=True
    )

    second_run = subprocess.run(
        ["npm.cmd", "run", "report"],
        cwd=ENVIRONMENT,
        capture_output=True,
        text=True
    )

    assert first_run.returncode == 0
    assert second_run.returncode == 0

    assert first_run.stdout == second_run.stdout


def normalize_receipts(text):
    return re.sub(
        r"RECEIPT=[^ ]+",
        "RECEIPT=<id>",
        text
    )


def test_output_matches_expected_report():
    result = subprocess.run(
        ["npm.cmd", "run", "report"],
        cwd=ENVIRONMENT,
        capture_output=True,
        text=True
    )

    assert result.returncode == 0, (
        f"Publisher failed:\n{result.stdout}\n{result.stderr}"
    )

    actual = normalize_receipts(result.stdout.strip())
    expected = normalize_receipts(
        EXPECTED_REPORT.read_text().strip()
    )

    # npm adds its own command banner, so keep only publisher output.
    actual_lines = [
        line
        for line in actual.splitlines()
        if line.startswith("BUNDLE ")
    ]

    expected_lines = [
        line
        for line in expected.splitlines()
        if line.startswith("BUNDLE ")
    ]

    assert actual_lines == expected_lines

def test_publications_are_persisted_in_duckdb():
    db_path = ENVIRONMENT / "releases.duckdb"

    assert db_path.exists(), (
        "releases.duckdb was not created"
    )

    connection = duckdb.connect(str(db_path), read_only=True)

    try:
        rows = connection.execute(
            """
            SELECT
                bundle_id,
                request_token,
                publication_id,
                status
            FROM publications
            ORDER BY bundle_id
            """
        ).fetchall()

        assert len(rows) == 3

        expected_bundles = [
            "BND-101",
            "BND-102",
            "BND-103"
        ]

        assert [row[0] for row in rows] == expected_bundles

        for bundle_id, request_token, publication_id, status in rows:
            assert request_token == f"token-{bundle_id}"
            assert publication_id
            assert status == "PUBLISHED"

    finally:
        connection.close()

def sign_descriptor(descriptor, cert_path, key_path):
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        descriptor_path = temp_path / "descriptor.bin"
        signature_path = temp_path / "signature.pem"

        # Write the exact UTF-8 bytes that will be sent as descriptor
        descriptor_path.write_bytes(
            descriptor.encode("utf-8")
        )

        subprocess.run(
            [
                "openssl",
                "cms",
                "-sign",
                "-in",
                str(descriptor_path),
                "-signer",
                str(cert_path),
                "-inkey",
                str(key_path),
                "-outform",
                "PEM",
                "-out",
                str(signature_path),
                "-binary"
            ],
            check=True,
            capture_output=True,
            text=True
        )

        return signature_path.read_text(encoding="utf-8")
    
def test_current_key_signature_is_accepted():
    descriptor = json.dumps(
        {
            "artifact_count": 1,
            "bundle_id": "BND-TEST-CURRENT",
            "total_bytes": 100
        },
        sort_keys=True,
        separators=(",", ":")
    )

    signature = sign_descriptor(
        descriptor,
        CURRENT_CERT,
        CURRENT_KEY
    )

    payload = json.dumps(
        {
            "descriptor": descriptor,
            "signature": signature,
            "request_token": "test-current-key-token"
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        "http://127.0.0.1:7070/v1/publications",
        data=payload,
        headers={
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(request) as response:
            response_body = response.read().decode("utf-8")


    except urllib.error.HTTPError as error:
        response_body = error.read().decode("utf-8")
        print("HTTP Status:", error.code)
        print("Gateway error:", response_body)

        result = json.loads(response_body)
        assert False, f"Gateway returned error: {result}"

    result = json.loads(response_body)

    assert result["status"] == "PUBLISHED"
    assert result["request_token"] == "test-current-key-token"
    assert result["publication_id"]

def test_revoked_key_signature_is_rejected():
    descriptor = json.dumps(
        {
            "artifact_count": 1,
            "bundle_id": "BND-TEST-REVOKED",
            "total_bytes": 100
        },
        sort_keys=True,
        separators=(",", ":")
    )

    signature = sign_descriptor(
        descriptor,
        REVOKED_CERT,
        REVOKED_KEY
    )

    payload = json.dumps(
        {
            "descriptor": descriptor,
            "signature": signature,
            "request_token": "test-revoked-key-token"
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        "http://127.0.0.1:7070/v1/publications",
        data=payload,
        headers={
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:
        urllib.request.urlopen(request)

        assert False, (
            "Revoked key should not be accepted by the gateway"
        )

    except urllib.error.HTTPError as error:
        assert error.code == 400

        response_body = error.read().decode("utf-8")
        result = json.loads(response_body)

        assert result["error"] == "UNTRUSTED_SIGNATURE"