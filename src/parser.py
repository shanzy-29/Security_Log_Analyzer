"""
parser.py — Reads the raw log file and separates valid records from malformed ones.

This module does NOT interpret meaning. It only checks structure:
  - correct field count
  - valid timestamp
  - known event type
  - not blank / not a comment

It returns two lists:
  - valid_records : list of raw records (tuples) ready for the normalizer
  - bad_records   : list of dicts {line, raw, reason}
"""

import csv
import os
from datetime import datetime

# The exact field count a valid line must have
EXPECTED_FIELD_COUNT = 5

# The exact timestamp format we accept
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

# Known event types (add/remove as your dataset requires)
KNOWN_EVENT_TYPES = {
    "LOGIN_SUCCESS",
    "LOGIN_FAIL",
    "ACCOUNT_CREATED",
    "ACCESS_DENIED",
    "PRIVILEGE_CHANGE",
}


# ---------------------------------------------------------------------------
# Function 1: is_valid_timestamp
# ---------------------------------------------------------------------------
def is_valid_timestamp(s):
    """Return True if s parses as 'YYYY-MM-DD HH:MM:SS', else False."""
    try:
        datetime.strptime(s.strip(), TIMESTAMP_FORMAT)
        return True
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------------------
# Function 2: parse_line
# ---------------------------------------------------------------------------
def parse_line(line, line_number):
    """
    Validate one raw line.

    Returns:
      ("ok", record_tuple)          if the line is valid
      ("bad", {line, raw, reason})  if the line is malformed
    """
    raw = line.rstrip("\n").rstrip("\r")

    # 1. Blank line
    if not raw.strip():
        return "bad", {"line": line_number, "raw": raw, "reason": "blank line"}

    # 2. Comment line (starts with #)
    if raw.strip().startswith("#"):
        return "bad", {"line": line_number, "raw": raw, "reason": "comment line"}

    # 3. Split by comma
    fields = [f.strip() for f in raw.split(",")]

    # 4. Field count check
    if len(fields) != EXPECTED_FIELD_COUNT:
        return "bad", {
            "line": line_number,
            "raw": raw,
            "reason": f"expected {EXPECTED_FIELD_COUNT} fields, got {len(fields)}",
        }

    timestamp, event_type, username, source_ip, message = fields

    # 5. Timestamp check
    if not is_valid_timestamp(timestamp):
        return "bad", {
            "line": line_number,
            "raw": raw,
            "reason": f"invalid timestamp: {timestamp!r}",
        }

    # 6. Event type check
    if event_type.upper() not in KNOWN_EVENT_TYPES:
        return "bad", {
            "line": line_number,
            "raw": raw,
            "reason": f"unknown event type: {event_type!r}",
        }

    # 7. Required-field emptiness check (message may be empty)
    if not username or not source_ip:
        return "bad", {
            "line": line_number,
            "raw": raw,
            "reason": "missing username or source_ip",
        }

    # Valid — return the raw record (kept as strings; normalizer parses later)
    return "ok", (timestamp, event_type.upper(), username, source_ip, message)


# ---------------------------------------------------------------------------
# Function 3: parse_file
# ---------------------------------------------------------------------------
def parse_file(path):
    """
    Read the whole file and return (valid_records, bad_records).

    Never raises — if the file can't be opened, returns empty valid list and
    one bad entry explaining why.
    """
    valid_records = []
    bad_records = []

    if not os.path.isfile(path):
        bad_records.append({
            "line": 0,
            "raw": "",
            "reason": f"file not found: {path}",
        })
        return valid_records, bad_records

    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as e:
        bad_records.append({
            "line": 0,
            "raw": "",
            "reason": f"cannot open file: {e}",
        })
        return valid_records, bad_records

    # Skip header if the first non-blank line looks like a header
    start_index = 0
    if lines:
        first = lines[0].strip().lower()
        if first.startswith("timestamp") or "event_type" in first:
            start_index = 1

    for i in range(start_index, len(lines)):
        line_number = i + 1  # 1-based, matches what a user sees in a text editor
        status, result = parse_line(lines[i], line_number)

        if status == "ok":
            valid_records.append(result)
        else:
            bad_records.append(result)

    return valid_records, bad_records


# ---------------------------------------------------------------------------
# Function 4: write_error_log
# ---------------------------------------------------------------------------
def write_error_log(bad_records, path="parser_errors.log"):
    """Write every rejected line and its reason to a log file."""
    if not bad_records:
        return

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("line,reason,raw\n")
            writer = csv.writer(f)
            for rec in bad_records:
                writer.writerow([rec["line"], rec["reason"], rec["raw"]])
    except OSError:
        # Never crash on log-writing failure — just print a warning
        print(f"[warn] could not write error log to {path}")


# ---------------------------------------------------------------------------
# Manual test — run this file directly to see the output
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    sample_path = "data/sample_logs.csv"
    if os.path.isfile(sample_path):
        valid, bad = parse_file(sample_path)
        print(f"Valid records: {len(valid)}")
        print(f"Bad records:   {len(bad)}")
        for rec in bad:
            print("  -", rec)
        write_error_log(bad)
    else:
        print(f"No sample file at {sample_path}. Create one first.")
