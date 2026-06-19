"""Backward-compatible demo entry point for the Automotive Security Test Bench.

For the full CLI, install the project and run:
    auto-sec-bench assess --input examples/ecu_risks.json
"""

from automotive_security_bench.cli import main


if __name__ == "__main__":
    raise SystemExit(main(["assess", "--input", "examples/ecu_risks.json"]))
