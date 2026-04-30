from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fibrum_pdf import to_json


def main() -> None:
    root = Path(__file__).resolve().parent
    pdf = root / "test_data" / "pdfs" / "nist.pdf"

    with tempfile.TemporaryDirectory() as tmp:
        output = (Path(tmp) / "nist.json").resolve()
        result = to_json(pdf, output=output)

        if result.path != output:
            raise AssertionError(f"unexpected result path: {result.path}")
        if not output.exists():
            raise AssertionError("to_json did not create the output file")

        data = json.loads(output.read_text(encoding="utf-8"))
        if not isinstance(data, list) or not data:
            raise AssertionError("expected a non-empty list of pages")
        if not isinstance(data[0], dict) or "data" not in data[0]:
            raise AssertionError("first page does not contain page data")

        pages = result.collect()
        if len(pages) != len(data):
            raise AssertionError(f"page count mismatch: {len(pages)} != {len(data)}")

        print(f"ok: converted {pdf} to {output} ({len(data)} pages)")


if __name__ == "__main__":
    main()
