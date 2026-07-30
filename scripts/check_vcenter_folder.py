#!/usr/bin/env python3
"""Verify the VM-folder calls against a REAL vCenter -- read-only by default.

Phase 10 checks that `vcenter.folder` exists and creates it if not. Those calls
cannot be proven with mocks: the exact query-parameter spelling and the VIM
login differ between vCenter versions. This script exercises them directly.

    python3 scripts/check_vcenter_folder.py -c <cluster>
    python3 scripts/check_vcenter_folder.py -c <cluster> --create-test-folder

Without --create-test-folder nothing is modified: it only logs in and lists the
VM folders. The password is asked interactively -- never an argument, never an
environment variable, never written anywhere.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import yaml  # noqa: E402

from ws1access.vcenter import VCenter, VCenterError  # noqa: E402

TEST_FOLDER = "axs-apitest"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--cluster", required=True,
                    help="cluster folder under clusters/")
    ap.add_argument("--create-test-folder", action="store_true",
                    help=f"also CREATE the folder {TEST_FOLDER!r} (modifies vCenter)")
    args = ap.parse_args()

    cfg_path = Path("clusters") / args.cluster / "config.yml"
    cfg = yaml.safe_load(cfg_path.read_text())
    vc = cfg["vcenter"]
    dc, want = vc["datacenter"], (vc.get("folder") or "").strip()
    print(f"vCenter : {vc['host']}  user {vc['user']}")
    print(f"datacenter: {dc}   configured folder: {want or '(none)'}")

    pw = getpass.getpass("vCenter password: ")
    client = VCenter(host=vc["host"], user=vc["user"], password=pw)

    try:
        print("\n[1] Automation API login ...")
        client.session()
        print("    ok")

        print("[2] resolve datacenter ...")
        dc_id = client.datacenter_id(dc)
        print(f"    {dc} -> {dc_id}")

        print("[3] list VM folders ...")
        folders = client.vm_folders(dc)
        for name, moid in sorted(folders.items()):
            print(f"    {name:<30} {moid}")
        if want:
            print(f"    configured folder {want!r}: "
                  f"{'EXISTS' if want in folders else 'MISSING -> phase 10 would create it'}")

        if args.create_test_folder:
            print(f"\n[4] VIM API: create {TEST_FOLDER!r} ...")
            moid = client.create_vm_folder(dc, TEST_FOLDER)
            print(f"    created -> {moid}")
            print(f"    NOTE: delete {TEST_FOLDER!r} in vCenter when you are done.")
        else:
            print("\n[4] skipped (pass --create-test-folder to test creation)")
    except VCenterError as e:
        print(f"\nFAILED: {e}")
        return 1
    print("\nAll checked calls succeeded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
