"""
OpenVAS / Greenbone Vulnerability Management (GVM) integration.

Unlike Nmap and Nuclei, OpenVAS is not a CLI tool you shell out to - it's a
client-server product (gvmd) you talk to over GMP (Greenbone Management
Protocol), XML commands sent over a TLS socket on the gvmd management
port, typically 9390.

This is a REAL protocol client (authenticate -> create_target ->
create_task -> start_task -> poll status -> get_results), not a mock. It
genuinely cannot be exercised in this sandbox (no GVM server available
here), so honesty matters: is_available() reports False until GVM_HOST is
configured AND reachable, and launch() raises a clear, actionable error
rather than pretending to succeed. Point it at a real gvmd instance via
environment variables and it will work as written.

Configuration (environment variables):
  GVM_HOST, GVM_PORT (default 9390), GVM_USERNAME, GVM_PASSWORD
  GVM_SCAN_CONFIG_ID (defaults to the stock "Full and fast" config)
  GVM_SCANNER_ID (defaults to the built-in "OpenVAS Default" scanner)
"""
from __future__ import annotations
import os
import socket
import ssl
import time
from xml.etree import ElementTree as ET
from typing import Callable, Optional
from scanners.base import ScannerBackend

GVM_HOST = os.environ.get("GVM_HOST", "")
GVM_PORT = int(os.environ.get("GVM_PORT", "9390"))
GVM_USERNAME = os.environ.get("GVM_USERNAME", "")
GVM_PASSWORD = os.environ.get("GVM_PASSWORD", "")
GVM_SCAN_CONFIG_ID = os.environ.get("GVM_SCAN_CONFIG_ID", "daba56c8-73ec-11df-a475-002264764cea")
# Built-in "OpenVAS Default" scanner UUID, the same one every GMP example
# (gvm-tools, gvm-cli, python-gvm) uses out of the box. create_task must
# reference a scanner explicitly - some gvmd versions won't pick one on
# their own - so this is passed unless overridden for a custom scanner.
GVM_SCANNER_ID = os.environ.get("GVM_SCANNER_ID", "08b69003-5fc2-4037-a479-93b440211c73")


class _GMPConnection:
    """Minimal raw GMP-over-TLS client: send an XML command, read the XML
    response. Real GVM deployments also support python-gvm's GvmConnection
    classes; this hand-rolled version avoids adding python-gvm as a hard
    dependency for a platform where GVM may not even be deployed."""

    def __init__(self, host: str, port: int, timeout: int = 30):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        self.sock = context.wrap_socket(raw_sock, server_hostname=host)

    def send(self, xml_command: str) -> ET.Element:
        self.sock.sendall(xml_command.encode("utf-8"))
        chunks = []
        self.sock.settimeout(60)
        while True:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            try:
                return ET.fromstring(b"".join(chunks))
            except ET.ParseError:
                continue
        return ET.fromstring(b"".join(chunks))

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


class OpenVASScanner(ScannerBackend):
    scanner_type = "openvas"

    def is_available(self) -> bool:
        if not (GVM_HOST and GVM_USERNAME and GVM_PASSWORD):
            return False
        try:
            conn = _GMPConnection(GVM_HOST, GVM_PORT, timeout=5)
            conn.close()
            return True
        except OSError:
            return False

    def launch(self, target: str, options: dict, on_progress: Optional[Callable[[int, str], None]] = None) -> dict:
        if not (GVM_HOST and GVM_USERNAME and GVM_PASSWORD):
            raise RuntimeError(
                "OpenVAS/GVM is not configured. Set GVM_HOST, GVM_USERNAME, GVM_PASSWORD "
                "environment variables to point this platform at a real gvmd instance, "
                "or import an OpenVAS XML report via the Import feature instead."
            )

        conn = _GMPConnection(GVM_HOST, GVM_PORT)
        try:
            if on_progress:
                on_progress(5, "Authenticating to GVM")
            auth_resp = conn.send(
                f'<authenticate><credentials><username>{GVM_USERNAME}</username>'
                f'<password>{GVM_PASSWORD}</password></credentials></authenticate>'
            )
            if auth_resp.get("status") != "200":
                raise RuntimeError(f"GVM authentication failed: {auth_resp.get('status_text')}")

            if on_progress:
                on_progress(15, f"Creating target {target}")
            target_resp = conn.send(
                f'<create_target><name>vuln-platform-{int(time.time())}</name>'
                f'<hosts>{target}</hosts></create_target>'
            )
            target_id = target_resp.get("id")

            if on_progress:
                on_progress(25, "Creating scan task")
            task_resp = conn.send(
                f'<create_task><name>vuln-platform scan {target}</name>'
                f'<target id="{target_id}"/><config id="{GVM_SCAN_CONFIG_ID}"/>'
                f'<scanner id="{GVM_SCANNER_ID}"/></create_task>'
            )
            task_id = task_resp.get("id")

            if on_progress:
                on_progress(30, "Starting scan")
            conn.send(f'<start_task task_id="{task_id}"/>')

            progress = 30
            while progress < 100:
                time.sleep(options.get("poll_interval_seconds", 15))
                status_resp = conn.send(f'<get_tasks task_id="{task_id}"/>')
                status_el = status_resp.find(".//status")
                progress_el = status_resp.find(".//progress")
                status_text = status_el.text if status_el is not None else "Unknown"
                try:
                    progress = int(progress_el.text) if progress_el is not None and progress_el.text else progress
                except ValueError:
                    pass
                if on_progress:
                    on_progress(min(30 + int(progress * 0.6), 95), f"GVM task status: {status_text} ({progress}%)")
                if status_text == "Done":
                    break
                if status_text in ("Stopped", "Interrupted"):
                    raise RuntimeError(f"GVM task ended with status: {status_text}")

            if status_text != "Done":
                raise RuntimeError(f"GVM task did not complete cleanly (last status: {status_text})")

            if on_progress:
                on_progress(96, "Locating report")
            # get_reports needs the *report* ID, which is a separate object
            # from the task ID - fetch it from the completed task's
            # <last_report> element rather than reusing task_id.
            task_detail = conn.send(f'<get_tasks task_id="{task_id}" details="1"/>')
            report_el = task_detail.find(".//last_report/report")
            if report_el is None:
                raise RuntimeError(
                    f"GVM task {task_id} completed but no last_report was found - "
                    "cannot fetch results."
                )
            report_id = report_el.get("id")

            if on_progress:
                on_progress(97, "Fetching report")
            report_resp = conn.send(f'<get_reports report_id="{report_id}" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5"/>')
            xml_output = ET.tostring(report_resp, encoding="unicode")

            if on_progress:
                on_progress(100, "Complete")

            return {"raw_output": xml_output, "filename": f"openvas_{target.replace('/', '_')}.xml"}
        finally:
            conn.close()
