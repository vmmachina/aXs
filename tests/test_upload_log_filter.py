"""During an OVA upload the live-log box shows messages, not a wall of percent.

ovftool prints "Disk progress: NN%" hundreds of times (each overwriting the last
via a carriage return). The top progress bar already shows that percentage, so
in the live-log box it is pure noise. `_quiet_upload` drops those lines and keeps
everything else -- so a stalled or complaining ovftool is still visible.
"""

from __future__ import annotations

import unittest

from ws1access.phases.p10_vms import _quiet_upload

# A carriage-return progress run, the way ovftool emits it, wrapped in the
# real header/footer lines and one warning.
SAMPLE = (
    "Opening OVA source: input/ova/alma.ova\n"
    "Opening VI target: vi://vc01/...\n"
    "Deploying to VI: vi://vc01/...\n"
    "Disk progress: 1%\rDisk progress: 2%\rDisk progress: 99%\r"
    "Disk progress:\r\n"
    "Transfer Completed\n"
    "Warning: lease timed out once, retried\n"
    "Completed successfully\n"
)


class TestQuietUpload(unittest.TestCase):
    def test_the_progress_lines_are_gone(self):
        self.assertNotIn("Disk progress", _quiet_upload(SAMPLE))

    def test_a_bare_percentage_continuation_is_also_dropped(self):
        # If ovftool ever splits the label from the number.
        self.assertEqual(_quiet_upload("Disk progress: 5%\r6%\r7%\n").strip(), "")

    def test_the_real_messages_survive(self):
        out = _quiet_upload(SAMPLE)
        for keep in ("Opening OVA source", "Opening VI target", "Deploying to VI",
                     "Transfer Completed", "Completed successfully"):
            self.assertIn(keep, out, keep)

    def test_a_warning_or_error_is_never_hidden(self):
        # The whole reason the live log exists for this phase: a complaining
        # ovftool must not look like a working one.
        out = _quiet_upload(SAMPLE)
        self.assertIn("Warning: lease timed out", out)
        self.assertIn("Error: cannot open target",
                      _quiet_upload("Disk progress: 50%\rError: cannot open target\n"))

    def test_output_with_no_progress_at_all_is_untouched(self):
        text = "Opening OVA source: x\nCompleted successfully\n"
        self.assertEqual(_quiet_upload(text),
                         "Opening OVA source: x\nCompleted successfully")

    def test_a_partial_disk_line_from_a_cut_chunk_is_dropped(self):
        # A read chunk can end mid-line, leaving "Disk p". The exact prefix
        # "Disk progress:" missed it; the operator saw it pop up.
        out = _quiet_upload("Deploying to VI: vi://x\nDisk p")
        self.assertNotIn("Disk", out)
        self.assertIn("Deploying to VI", out)

    def test_the_whole_certificate_block_is_dropped(self):
        # The base64 wall that pops up mid-upload -- including its SHORT last
        # line, which a per-line 40+ base64 rule would have let through.
        text = ("Opening VI target: vi://x\n"
                "-----BEGIN CERTIFICATE-----\n"
                "Vj7o4vRSoePGXldGC18tZVknQLczb9JvhBkPjaBmvtM5fRW/X0OjVbB95zWTx\n"
                "nnBGkrdKUdHqDj/SHHnV39+\n"                 # short last line
                "-----END CERTIFICATE-----\n"
                "Transfer Completed\n")
        out = _quiet_upload(text)
        self.assertNotIn("CERTIFICATE", out)
        self.assertNotIn("Vj7o4vRS", out)
        self.assertNotIn("nnBGkrdK", out)
        self.assertIn("Opening VI target", out)
        self.assertIn("Transfer Completed", out)

    def test_an_unterminated_certificate_drops_to_the_end(self):
        # A chunk that cut mid-certificate: BEGIN seen, no END yet. Everything
        # after BEGIN is base64, so dropping to the end is correct.
        text = ("Deploying to VI: vi://x\n"
                "-----BEGIN CERTIFICATE-----\n"
                "Vj7o4vRSoePGXldGC18tZVknQLczb9JvhBkPjaBmvtM5fRW/X0OjVbB95zWTx\n")
        out = _quiet_upload(text)
        self.assertEqual(out, "Deploying to VI: vi://x")


if __name__ == "__main__":
    unittest.main()
