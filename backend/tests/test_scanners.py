from __future__ import annotations

import time
from unittest.mock import MagicMock, patch
import pytest

from scanners.nuclei_scanner import NucleiScanner
from scanners.nmap_scanner import NmapScanner
from scanners.base import ScannerCancelled


def test_nuclei_scanner_command_generation_optimized():
    scanner = NucleiScanner()
    with patch("shutil.which", return_value="/usr/local/bin/nuclei"), \
         patch("subprocess.Popen") as mock_popen, \
         patch("os.path.exists", return_value=True), \
         patch("builtins.open", MagicMock()):
        
        mock_proc = MagicMock()
        mock_proc.poll.side_effect = [None, 0, 0, 0, 0]
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = ("", "")
        mock_popen.return_value = mock_proc

        scanner.launch("example.com", {"severity_profile": "standard", "automatic_scan": True})
        
        args = mock_popen.call_args[0][0]
        assert "nuclei" in args
        assert "-u" in args
        assert "example.com" in args
        assert "-c" in args
        assert args[args.index("-c") + 1] == "50"
        assert "-rl" in args
        assert args[args.index("-rl") + 1] == "300"
        assert "-timeout" in args
        assert args[args.index("-timeout") + 1] == "5"
        assert "-as" in args
        assert "-severity" in args
        assert "critical" in args[args.index("-severity") + 1]


def test_nuclei_scanner_exit_code_1_treated_as_clean_scan():
    """Nuclei returns exit code 1 when no vulnerability matches are found. It must not raise an error."""
    scanner = NucleiScanner()
    with patch("shutil.which", return_value="/usr/local/bin/nuclei"), \
         patch("subprocess.Popen") as mock_popen, \
         patch("os.path.exists", return_value=True), \
         patch("builtins.open", MagicMock()):
        
        mock_proc = MagicMock()
        mock_proc.poll.side_effect = [None, 1, 1, 1, 1]
        mock_proc.returncode = 1
        mock_proc.communicate.return_value = ("", "")
        mock_popen.return_value = mock_proc

        result = scanner.launch("example.com", {})
        assert "raw_output" in result


def test_nuclei_scanner_periodic_heartbeat():
    scanner = NucleiScanner()
    with patch("shutil.which", return_value="/usr/local/bin/nuclei"), \
         patch("subprocess.Popen") as mock_popen, \
         patch("os.path.exists", return_value=True), \
         patch("builtins.open", MagicMock()):

        progress_calls = []
        def on_progress(pct, msg):
            progress_calls.append((pct, msg))

        mock_proc = MagicMock()
        mock_proc.poll.side_effect = [None, None, 0, 0, 0]
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = ("", "")
        mock_popen.return_value = mock_proc

        timeline = [0.0, 6.0, 12.0, 12.1, 12.2, 12.3, 12.4, 12.5]
        time_index = [0]
        def fake_monotonic():
            val = timeline[min(time_index[0], len(timeline) - 1)]
            time_index[0] += 1
            return val

        with patch("time.monotonic", side_effect=fake_monotonic), \
             patch("time.sleep", return_value=None):
            scanner.launch("example.com", {}, on_progress=on_progress)

        assert len(progress_calls) >= 3
        assert progress_calls[0][0] == 5
        assert progress_calls[-1][0] == 100
        heartbeat_msgs = [msg for pct, msg in progress_calls if "elapsed" in msg]
        assert len(heartbeat_msgs) >= 1


def test_nmap_scanner_command_generation_optimized():
    scanner = NmapScanner()
    with patch("shutil.which", return_value="/usr/bin/nmap"), \
         patch("subprocess.Popen") as mock_popen, \
         patch("os.path.exists", return_value=True), \
         patch("builtins.open", MagicMock()):

        mock_proc = MagicMock()
        mock_proc.poll.side_effect = [0, 0, 0, 0]
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = ("", "")
        mock_popen.return_value = mock_proc

        scanner.launch("192.168.1.0/24", {"profile": "service_version"})
        args = mock_popen.call_args[0][0]

        assert "nmap" in args
        assert "-n" in args
        assert "--min-rate" in args
        assert args[args.index("--min-rate") + 1] == "300"
        assert "--host-timeout" in args


def test_nmap_scanner_resolve_dns_toggle():
    scanner = NmapScanner()
    with patch("shutil.which", return_value="/usr/bin/nmap"), \
         patch("subprocess.Popen") as mock_popen, \
         patch("os.path.exists", return_value=True), \
         patch("builtins.open", MagicMock()):

        mock_proc = MagicMock()
        mock_proc.poll.side_effect = [0, 0, 0, 0]
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = ("", "")
        mock_popen.return_value = mock_proc

        scanner.launch("10.0.0.1", {"profile": "service_version", "resolve_dns": True})
        args = mock_popen.call_args[0][0]
        assert "-n" not in args


def test_scanner_cancellation():
    scanner = NucleiScanner()
    with patch("shutil.which", return_value="/usr/local/bin/nuclei"), \
         patch("subprocess.Popen") as mock_popen:

        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        with pytest.raises(ScannerCancelled):
            scanner.launch("example.com", {"_cancel_check": lambda: True})
        
        mock_proc.terminate.assert_called_once()
