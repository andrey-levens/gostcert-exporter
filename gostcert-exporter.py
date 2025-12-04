from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_pem_pkcs7_certificates,
    load_der_pkcs7_certificates,
)
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import ExtensionNotFound, ObjectIdentifier

SEARCH_FOLDER = Path(".")
PORT = 8000
PRIVATE_KEY_OID = ObjectIdentifier("2.5.29.16")


def load_certificates_from_file(filepath: Path):
    data = filepath.read_bytes()

    # PKCS#7 PEM
    if data.lstrip().startswith(b"-----BEGIN PKCS7-----"):
        try:
            return list(load_pem_pkcs7_certificates(data))
        except Exception:
            pass

    if data[:2] in (b'0\x82', b'0\x83', b'0\x84'):  # типичные начала ASN.1 для PKCS#7
        try:
            # Этот вызов может выдать UserWarning — подавляем локально
            import warnings
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=UserWarning,
                                        message=".*PKCS#7 certificates could not be parsed as DER.*")
                return list(load_der_pkcs7_certificates(data))
        except Exception:
            pass

    # Обычный PEM/DER сертификат
    for loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
        try:
            cert = loader(data, default_backend())
            return [cert]
        except Exception:
            continue

    return []


def get_metrics() -> str:
    lines = [
        '# HELP cert_public_key_valid_from Начало действия сертификата (Unix timestamp)',
        '# TYPE cert_public_key_valid_from gauge',
        '# HELP cert_public_key_valid_to Окончание действия сертификата (Unix timestamp)',
        '# TYPE cert_public_key_valid_to gauge',
        '# HELP cert_private_key_valid_from Начало действия закрытого ключа (OID 2.5.29.16)',
        '# TYPE cert_private_key_valid_from gauge',
        '# HELP cert_private_key_valid_to Окончание действия закрытого ключа (OID 2.5.29.16)',
        '# TYPE cert_private_key_valid_to gauge',
    ]

    for cert_path in SEARCH_FOLDER.iterdir():
        if cert_path.suffix.lower() not in {".crt", ".pem", ".cer", ".der", ".p7b", ".p7c"}:
            continue

        certs = load_certificates_from_file(cert_path)
        if not certs:
            continue

        for idx, cert in enumerate(certs):
            label_name = cert_path.name if len(certs) == 1 else f"{cert_path.name}[{idx}]"
            labels = f'{{filename="{label_name}"}}'

            not_before = int(cert.not_valid_before_utc.timestamp())
            not_after = int(cert.not_valid_after_utc.timestamp())

            lines.append(f"cert_public_key_valid_from{labels} {not_before}")
            lines.append(f"cert_public_key_valid_to{labels} {not_after}")

            try:
                ext = cert.extensions.get_extension_for_oid(PRIVATE_KEY_OID)
                pk_usage = ext.value

                if pk_usage.not_before:
                    lines.append(f"cert_private_key_valid_from{labels} {int(pk_usage.not_before.timestamp())}")
                if pk_usage.not_after:
                    lines.append(f"cert_private_key_valid_to{labels} {int(pk_usage.not_after.timestamp())}")

            except ExtensionNotFound:
                pass
            except Exception as e:
                print(f"Ошибка Private Key Usage Period в {label_name}: {e}")

    return "\n".join(lines) + "\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.end_headers()
            self.wfile.write(get_metrics().encode("utf-8"))
        elif self.path in ("/", "/health", "/ready"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args, **kwargs):
        pass


if __name__ == "__main__":
    print(f"Экспортер запущен → http://localhost:{PORT}/metrics")
    try:
        HTTPServer(("", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")
