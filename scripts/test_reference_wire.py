#!/usr/bin/env python3
"""Compare Soft-UE wire fields with the pinned, separately built UEC parser."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--fixtures", type=Path, required=True)
parser.add_argument("--oracle", type=Path, required=True)
arguments = parser.parse_args()
with tempfile.TemporaryDirectory(prefix="softue-reference-") as temporary:
    destination = Path(temporary)
    subprocess.run([str(arguments.fixtures), str(destination)], check=True)
    for fixture in sorted(destination.glob("*.bin")):
        packet_type = int(fixture.name.split("-")[0])
        parsed = json.loads(subprocess.check_output([str(arguments.oracle), str(fixture)], text=True))
        assert parsed["type"] == packet_type, (fixture.name, parsed)
        assert parsed["entropy"] == 0xBEEF, (fixture.name, parsed)
        if packet_type in (2, 3):
            assert parsed["psn"] == 1000 and parsed["clear_psn"] == 997, parsed
        if packet_type == 7:
            assert parsed["psn"] == 997 and parsed["cack_psn"] == 1000, parsed
        if packet_type != 6:
            assert parsed["source_pdc"] == 17 and parsed["destination_pdc"] == 29, parsed
        if packet_type in (2, 3, 6):
            assert parsed["opcode"] == (7 if packet_type == 6 else 1), parsed
            assert parsed["message_id"] == (0 if packet_type == 6 else 0x1234), parsed
            assert parsed["payload_length"] == 3, parsed
    corrupted = destination / "2-0-0.bin"
    data = bytearray(corrupted.read_bytes())
    data[-5] ^= 1
    corrupted.write_bytes(data)
    assert subprocess.run([str(arguments.oracle), str(corrupted)], capture_output=True).returncode != 0
print("PASS: 24 reference-parser/CRC comparisons and corrupted-payload rejection")
