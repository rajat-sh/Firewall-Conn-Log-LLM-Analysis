import sqlite3
import os
import sys
import re
import json
import time
from typing import List, Tuple, Optional, Dict, Any

# --- DEPENDENCY IMPORTS ---
try:
    import requests
except ImportError:
    print("[!] The 'requests' library is not installed. Please install it (pip install requests).")
    sys.exit(1)


# --- CONFIGURATION ---
DB_NAME = 'asa_connections.db'
BATCH_SIZE = 5000
LLM_MODEL = 'gemini-2.5-flash-preview-09-2025'
LLM_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{LLM_MODEL}:generateContent"


# --- API KEY MANAGEMENT ---
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
if not GEMINI_API_KEY:
    print("""
[!] WARNING: GEMINI_API_KEY environment variable not found.
    This is required for the Natural Language Query Interface (LLM).

    >>> To fix this, set the environment variable in your terminal:
    >>> macOS/Linux: export GEMINI_API_KEY='YOUR_API_KEY_HERE'
    >>> Windows (CMD): set GEMINI_API_KEY=YOUR_API_KEY_HERE
    >>> Windows (PowerShell): $env:GEMINI_API_KEY='YOUR_API_KEY_HERE'
    (Replace 'YOUR_API_KEY_HERE' with your actual key.)
""")


# --- UTILS FOR PRINTING WITH DYNAMIC COLUMNS ---

def _is_blank(value: Any) -> bool:
    """
    Defines what is considered "blank" for the purpose of dropping an entire column:
    - None
    - empty string
    - 'NULL'
    - '-'
    - numeric 0
    """
    if value is None:
        return True
    if isinstance(value, (int, float)):
        return value == 0
    s = str(value).strip()
    return s == "" or s.upper() == "NULL" or s == "-"


def _filter_columns(headers: List[str], rows: List[Dict[str, Any]]) -> List[str]:
    """
    Given an ordered list of headers and a list of row dicts {col: value},
    return the subset of headers that have at least one non-blank value.
    """
    if not rows:
        return headers

    kept = []
    for h in headers:
        any_non_blank = any(not _is_blank(r.get(h)) for r in rows)
        if any_non_blank:
            kept.append(h)
    return kept


def _print_table_from_dicts(headers: List[str], rows: List[Dict[str, Any]]):
    """
    Generic tabular printer:
    - headers: ordered list of column names to print
    - rows: list of {col_name: value}
    Applies dynamic column-width computation.
    Skips if headers is empty.
    """
    if not headers:
        print("[!] Nothing to display (all columns were blank).")
        return

    # Compute column widths
    col_widths = {h: len(h) for h in headers}
    for r in rows:
        for h in headers:
            v = r.get(h)
            s = "" if v is None else str(v)
            if len(s) > col_widths[h]:
                col_widths[h] = len(s)

    # Add small padding
    for h in headers:
        col_widths[h] += 2

    # Build header line
    header_line = "".join(h.ljust(col_widths[h]) for h in headers)
    print(header_line)
    print("-" * len(header_line))

    # Build row lines
    for r in rows:
        line = "".join(
            (("" if r.get(h) is None else str(r.get(h))).ljust(col_widths[h]))
            for h in headers
        )
        print(line)
    print("-" * len(header_line))
    print()


# --- DATABASE UTILITIES & LOGIC ---

def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('DROP TABLE IF EXISTS connections')

    cursor.execute('''
        CREATE TABLE connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol TEXT,
            interface1 TEXT,
            ip_addr1 TEXT,
            port1 INTEGER,
            xlated_ip1 TEXT,
            xlated_port1 INTEGER,
            interface2 TEXT,
            ip_addr2 TEXT,
            port2 INTEGER,
            xlated_ip2 TEXT,
            xlated_port2 INTEGER,
            idle_time TEXT,
            uptime TEXT,
            bytes_transferred INTEGER,
            flags TEXT,
            initiator_ip TEXT,
            responder_ip TEXT
        )
    ''')
    conn.commit()
    print("\n--- DATABASE SCHEMA FOR LLM CONTEXT ---")
    print(
        "TABLE: connections (\n"
        "  id INTEGER PRIMARY KEY, protocol TEXT, interface1 TEXT, ip_addr1 TEXT, port1 INTEGER,\n"
        "  xlated_ip1 TEXT, xlated_port1 INTEGER, interface2 TEXT, ip_addr2 TEXT, port2 INTEGER,\n"
        "  xlated_ip2 TEXT, xlated_port2 INTEGER, idle_time TEXT, uptime TEXT, bytes_transferred INTEGER,\n"
        "  flags TEXT, initiator_ip TEXT, responder_ip TEXT\n"
        ")\n"
    )
    print("------------------------------------------")
    return conn

def _time_to_seconds(time_str: str) -> int:
    if not time_str:
        return 0

    if ':' in time_str:
        parts = [int(p) for p in time_str.split(':')]
        if len(parts) == 3:
            return parts[0] * 3600 + parts[1] * 60 + parts[2]
        elif len(parts) == 2:
            return parts[0] * 60 + parts[1]
        return 0

    total_seconds = 0

    m_match = re.search(r'(\d+)m', time_str)
    if m_match:
        total_seconds += int(m_match.group(1)) * 60

    s_match = re.search(r'(\d+)s', time_str)
    if s_match:
        total_seconds += int(s_match.group(1))

    return total_seconds

def _parse_ip_port_slash(ip_port_str: str) -> Tuple[str, int]:
    try:
        ip, port_str = ip_port_str.rsplit('/', 1)
        clean_port_str = port_str.replace(',', '').strip()
        return ip, int(clean_port_str)
    except ValueError:
        return ip_port_str.replace(',', '').strip(), 0

def _parse_format1_line(line: str) -> Optional[Tuple[Any, ...]]:
    match = re.search(
        r'(\w+)\s+([^:]+)\s+([^:]+:\d+)\s+([^:]+)\s+([^:]+:\d+),\s*idle\s+([^\s,]+),\s*bytes\s+(\d+),\s*flags\s+([^\s,]+)',
        line
    )

    if not match:
        return None

    try:
        protocol, int1, ip1_raw, int2_full, ip2_raw, idle_time, bytes_val_str, flags = match.groups()

        int2 = int2_full.strip()

        def parse_ip_port_colon(ip_port_str):
            try:
                ip, port_str = ip_port_str.rsplit(':', 1)
                return ip, int(port_str)
            except ValueError:
                return ip_port_str, 0

        ip_addr1, port1 = parse_ip_port_colon(ip1_raw)
        ip_addr2, port2 = parse_ip_port_colon(ip2_raw)

        data = (
            protocol, int1, ip_addr1, port1,
            None, None,
            int2, ip_addr2, port2,
            None, None,
            idle_time,
            None,
            int(bytes_val_str), flags,
            None,
            None
        )
        return data
    except Exception as e:
        print(f"[!] Format 1 Parsing Error on line: {line.strip()}. Error: {e}")
        return None

def _parse_format2_record(full_record: str) -> Optional[Tuple[Any, ...]]:
    main_match = re.search(
        r'^(UDP|TCP|ICMP|IP)\s+(\S+):\s*([\d\.]+/\d+)\s+(\S+):\s*([\d\.]+/\d+)',
        full_record
    )

    if not main_match:
        main_match = re.search(
            r'^(UDP|TCP|ICMP|IP)\s+(\S+):\s*([^,\s]+)\s+(\S+):\s*([^,\s]+)',
            full_record
        )
        if not main_match:
            return None

    protocol = main_match.group(1)
    int1 = main_match.group(2).replace(':', '')
    ip1_raw = main_match.group(3)
    int2 = main_match.group(4).replace(':', '')
    ip2_raw = main_match.group(5)

    ip_addr1, port1 = _parse_ip_port_slash(ip1_raw)
    ip_addr2, port2 = _parse_ip_port_slash(ip2_raw)

    flags_match = re.search(r'flags\s+([^\s,]+)', full_record)
    flags = flags_match.group(1).strip() if flags_match else ""

    idle_match = re.search(r'idle\s+([^\s,]+)', full_record)
    idle_time = idle_match.group(1).strip() if idle_match else ""

    uptime_match = re.search(r'uptime\s+([^\s,]+)', full_record)
    uptime = uptime_match.group(1).strip() if uptime_match else None

    bytes_match = re.search(r'bytes\s+(\d+)', full_record)
    bytes_val = int(bytes_match.group(1)) if bytes_match else 0

    init_resp_match = re.search(
        r'Initiator:\s*([^,\s]+),\s*Responder:\s*([^,\s]+)',
        full_record
    )
    initiator_ip = init_resp_match.group(1) if init_resp_match else None
    responder_ip = init_resp_match.group(2) if init_resp_match else None

    return (
        protocol, int1, ip_addr1, port1,
        None, None,
        int2, ip_addr2, port2,
        None, None,
        idle_time, uptime,
        bytes_val, flags,
        initiator_ip, responder_ip
    )

def _parse_format3_line(full_record: str) -> Optional[Tuple[Any, ...]]:
    main_regex = re.compile(
        r'^(UDP|TCP|ICMP|IP)\s+([^:\s]+):\s*([^/\s]+/[\d\.]+)\s*\(([^/\s]+/[\d\.]+)\)\s*'
        r'([^:\s]+):\s*([^/\s]+/[\d\.]+)\s*\(([^/\s]+/[\d\.]+)\)'
    )

    main_match = main_regex.search(full_record)

    if not main_match:
        return None

    try:
        protocol, int1, ip1_raw, xip1_raw, int2, ip2_raw, xip2_raw = main_match.groups()

        ip_addr1, port1 = _parse_ip_port_slash(ip1_raw)
        ip_addr2, port2 = _parse_ip_port_slash(ip2_raw)
        xlated_ip1, xlated_port1 = _parse_ip_port_slash(xip1_raw)
        xlated_ip2, xlated_port2 = _parse_ip_port_slash(xip2_raw)

        flags_match = re.search(r'flags\s+([^\s,]+)', full_record)
        flags = flags_match.group(1).strip() if flags_match else ""

        idle_match = re.search(r'idle\s+([^\s,]+)', full_record)
        idle_time = idle_match.group(1).strip() if idle_match else ""

        uptime_match = re.search(r'uptime\s+([^\s,]+)', full_record)
        uptime = uptime_match.group(1).strip() if uptime_match else None

        bytes_match = re.search(r'bytes\s+(\d+)', full_record)
        bytes_val = int(bytes_match.group(1)) if bytes_match else 0

        init_resp_match = re.search(
            r'Initiator:\s*([^,\s]+),\s*Responder:\s*([^,\s]+)',
            full_record
        )
        initiator_ip = init_resp_match.group(1) if init_resp_match else None
        responder_ip = init_resp_match.group(2) if init_resp_match else None

        data = (
            protocol, int1, ip_addr1, port1, xlated_ip1, xlated_port1,
            int2, ip_addr2, port2, xlated_ip2, xlated_port2,
            idle_time, uptime,
            bytes_val, flags,
            initiator_ip, responder_ip
        )
        return data
    except Exception as e:
        print(f"[!] Format 3 Internal Parsing Error on record: {full_record.strip()}. Error: {e}")
        return None

def process_file(conn: sqlite3.Connection, filename: str):
    cursor = conn.cursor()

    cursor.execute('DELETE FROM connections')
    conn.commit()
    print("[*] Database connections table cleared before processing.")

    data_batch = []
    total_processed = 0
    format_type = None

    try:
        with open(filename, 'r') as f:
            lines = f.readlines()

        # Format detection
        start_processing_index = 0
        for idx, line in enumerate(lines):
            stripped_line = line.strip()
            if not stripped_line:
                continue

            if re.search(r'^(UDP|TCP|ICMP|IP)\s+\w+:\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+\s+\(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+\)', stripped_line):
                format_type = 3
                start_processing_index = idx
                break
            elif re.search(r'^(UDP|TCP|ICMP|IP)\s+\w+\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\s+\w+\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+,\s*idle\s+([^\s,]+)', stripped_line):
                format_type = 1
                start_processing_index = idx
                break
            elif re.search(
                r'^(UDP|TCP|ICMP|IP)\s+\S+:\s+\d{1,3}(?:\.\d{1,3}){3}/\d+',
                stripped_line
            ):
                format_type = 2
                start_processing_index = idx
                break

        if format_type is None:
            print("[!] Error: Could not determine log format from the file content after scanning all lines. No valid connection record found.")
            return

        print(f"[*] Detected format: Format {format_type}")

        i = start_processing_index
        while i < len(lines):
            line = lines[i].strip()
            i += 1

            if not line:
                continue

            record_data = None
            full_record = line

            if format_type == 3:
                if i < len(lines) and lines[i].strip().startswith('Initiator:'):
                    full_record += " " + lines[i].strip()
                    i += 1
                record_data = _parse_format3_line(full_record)

            elif format_type == 2:
                if i < len(lines) and lines[i].startswith((' ', '\t')) and ('flags' in lines[i] or 'bytes' in lines[i]):
                    full_record += " " + lines[i].strip()
                    i += 1

                if i < len(lines) and lines[i].strip().startswith('Initiator:'):
                    full_record += " " + lines[i].strip()
                    i += 1

                record_data = _parse_format2_record(full_record)

            elif format_type == 1:
                record_data = _parse_format1_line(full_record)

            if record_data and len(record_data) == 17:
                data_batch.append(record_data)
                total_processed += 1
            elif record_data:
                print(f"[!] Warning: Parsed record has unexpected length {len(record_data)}. Expected 17. Skipping line: {full_record}")

            if len(data_batch) >= BATCH_SIZE:
                cursor.executemany('''
                    INSERT INTO connections (
                        protocol, interface1, ip_addr1, port1, xlated_ip1, xlated_port1,
                        interface2, ip_addr2, port2, xlated_ip2, xlated_port2,
                        idle_time, uptime, bytes_transferred, flags, initiator_ip, responder_ip
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', data_batch)
                conn.commit()
                data_batch = []

        if data_batch:
            cursor.executemany('''
                INSERT INTO connections (
                    protocol, interface1, ip_addr1, port1, xlated_ip1, xlated_port1,
                    interface2, ip_addr2, port2, xlated_ip2, xlated_port2,
                    idle_time, uptime, bytes_transferred, flags, initiator_ip, responder_ip
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', data_batch)
            conn.commit()
            total_processed += len(data_batch)

        print(f"[*] Successfully processed {total_processed} entries from {filename} into database.")

    except FileNotFoundError:
        print(f"[!] Error: File {filename} not found. Please ensure the log file exists and contains data.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An unexpected error occurred during file processing: {e}")
        sys.exit(1)


# --- REPORTING FUNCTIONS WITH DYNAMIC COLUMN REMOVAL ---

def print_database(conn):
    print("\n--- Database Entries (Detailed View, no ID) ---")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT protocol, interface1, ip_addr1, port1, xlated_ip1, xlated_port1,
               interface2, ip_addr2, port2, xlated_ip2, xlated_port2,
               idle_time, uptime, bytes_transferred, flags, initiator_ip, responder_ip
        FROM connections
    """)
    rows = cursor.fetchall()

    row_dicts = []
    for (proto, int1, ip1, port1, xip1, xport1,
         int2, ip2, port2, xip2, xport2,
         idle, uptime_val, bytes_t, flags, init_ip, resp_ip) in rows:

        ip1_port = f"{ip1}:{port1}" if port1 else (ip1 or "")
        ip2_port = f"{ip2}:{port2}" if port2 else (ip2 or "")
        xip1_port = f"{xip1}:{xport1}" if xip1 and xport1 else (xip1 or "")
        xip2_port = f"{xip2}:{xport2}" if xip2 and xport2 else (xip2 or "")

        row_dicts.append({
            "PROTO": proto,
            "IFACE1": int1,
            "IP1:PORT1": ip1_port,
            "X-IP1:X-PORT1": xip1_port,
            "IFACE2": int2,
            "IP2:PORT2": ip2_port,
            "X-IP2:X-PORT2": xip2_port,
            "BYTES": bytes_t,
            "IDLE": idle or "",
            "UPTIME": uptime_val or "",
            "FLAGS": flags or "",
            "INIT_IP": init_ip or "",
            "RESP_IP": resp_ip or "",
        })

    headers = ["PROTO", "IFACE1", "IP1:PORT1", "X-IP1:X-PORT1", "IFACE2",
               "IP2:PORT2", "X-IP2:X-PORT2", "BYTES", "IDLE", "UPTIME",
               "FLAGS", "INIT_IP", "RESP_IP"]
    headers = _filter_columns(headers, row_dicts)
    _print_table_from_dicts(headers, row_dicts)

def print_top_bytes_entries(conn, limit=50):
    print(f"\n--- Top {limit} Connections by Bytes Transferred (Descending, no ID) ---")
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            protocol, interface1, ip_addr1, port1, xlated_ip1, xlated_port1,
            interface2, ip_addr2, port2, xlated_ip2, xlated_port2,
            bytes_transferred, idle_time, uptime, flags, initiator_ip, responder_ip
        FROM
            connections
        ORDER BY
            bytes_transferred DESC, id DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()

    row_dicts = []
    for (proto, int1, ip1, port1, xip1, xport1,
         int2, ip2, port2, xip2, xport2,
         bytes_t, idle, uptime_val, flags, init_ip, resp_ip) in rows:

        ip1_port = f"{ip1}:{port1}" if port1 else (ip1 or "")
        ip2_port = f"{ip2}:{port2}" if port2 else (ip2 or "")
        xip1_port = f"{xip1}:{xport1}" if xip1 and xport1 else (xip1 or "")
        xip2_port = f"{xip2}:{xport2}" if xip2 and xport2 else (xip2 or "")

        row_dicts.append({
            "PROTO": proto,
            "BYTES": bytes_t,
            "IFACE1": int1,
            "IP1:PORT1": ip1_port,
            "X-IP1:X-PORT1": xip1_port,
            "IFACE2": int2,
            "IP2:PORT2": ip2_port,
            "X-IP2:X-PORT2": xip2_port,
            "IDLE": idle or "",
            "UPTIME": uptime_val or "",
            "FLAGS": flags or "",
        })

    headers = ["PROTO", "BYTES", "IFACE1", "IP1:PORT1", "X-IP1:X-PORT1",
               "IFACE2", "IP2:PORT2", "X-IP2:X-PORT2", "IDLE", "UPTIME", "FLAGS"]
    headers = _filter_columns(headers, row_dicts)
    _print_table_from_dicts(headers, row_dicts)

def print_top_idle_time_entries(conn, limit=50):
    print(f"\n--- Top {limit} Connections by Idle Time (Descending, no ID) ---")
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            protocol, interface1, ip_addr1, port1, xlated_ip1, xlated_port1,
            interface2, ip_addr2, port2, xlated_ip2, xlated_port2,
            idle_time, uptime, bytes_transferred, flags
        FROM
            connections
    ''')
    rows = cursor.fetchall()

    sorted_rows = sorted(
        rows,
        key=lambda r: _time_to_seconds(r[11] or "0s"),
        reverse=True
    )
    rows_to_display = sorted_rows[:limit]

    row_dicts = []
    for (proto, int1, ip1, port1, xip1, xport1,
         int2, ip2, port2, xip2, xport2,
         idle, uptime_val, bytes_t, flags) in rows_to_display:

        ip1_port = f"{ip1}:{port1}" if port1 else (ip1 or "")
        ip2_port = f"{ip2}:{port2}" if port2 else (ip2 or "")
        xip1_port = f"{xip1}:{xport1}" if xip1 and xport1 else (xip1 or "")
        xip2_port = f"{xip2}:{xport2}" if xip2 and xport2 else (xip2 or "")

        row_dicts.append({
            "PROTO": proto,
            "IDLE": idle or "",
            "UPTIME": uptime_val or "",
            "IFACE1": int1,
            "IP1:PORT1": ip1_port,
            "X-IP1:X-PORT1": xip1_port,
            "IFACE2": int2,
            "IP2:PORT2": ip2_port,
            "X-IP2:X-PORT2": xip2_port,
            "BYTES": bytes_t,
            "FLAGS": flags or "",
        })

    headers = ["PROTO", "IDLE", "UPTIME", "IFACE1", "IP1:PORT1", "X-IP1:X-PORT1",
               "IFACE2", "IP2:PORT2", "X-IP2:X-PORT2", "BYTES", "FLAGS"]
    headers = _filter_columns(headers, row_dicts)
    _print_table_from_dicts(headers, row_dicts)

def print_top_uptime_entries(conn, limit=50):
    print(f"\n--- Top {limit} Connections by Uptime (Descending, no ID) ---")
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            protocol, interface1, ip_addr1, port1, xlated_ip1, xlated_port1,
            interface2, ip_addr2, port2, xlated_ip2, xlated_port2,
            idle_time, uptime, bytes_transferred, flags
        FROM
            connections
    ''')
    rows = cursor.fetchall()

    sorted_rows = sorted(
        rows,
        key=lambda r: _time_to_seconds(r[12] or "0s"),
        reverse=True
    )
    rows_to_display = sorted_rows[:limit]

    row_dicts = []
    for (proto, int1, ip1, port1, xip1, xport1,
         int2, ip2, port2, xip2, xport2,
         idle, uptime_val, bytes_t, flags) in rows_to_display:

        ip1_port = f"{ip1}:{port1}" if port1 else (ip1 or "")
        ip2_port = f"{ip2}:{port2}" if port2 else (ip2 or "")
        xip1_port = f"{xip1}:{xport1}" if xip1 and xport1 else (xip1 or "")
        xip2_port = f"{xip2}:{xport2}" if xip2 and xport2 else (xip2 or "")

        row_dicts.append({
            "PROTO": proto,
            "UPTIME": uptime_val or "",
            "IDLE": idle or "",
            "IFACE1": int1,
            "IP1:PORT1": ip1_port,
            "X-IP1:X-PORT1": xip1_port,
            "IFACE2": int2,
            "IP2:PORT2": ip2_port,
            "X-IP2:X-PORT2": xip2_port,
            "BYTES": bytes_t,
            "FLAGS": flags or "",
        })

    headers = ["PROTO", "UPTIME", "IDLE", "IFACE1", "IP1:PORT1", "X-IP1:X-PORT1",
               "IFACE2", "IP2:PORT2", "X-IP2:X-PORT2", "BYTES", "FLAGS"]
    headers = _filter_columns(headers, row_dicts)
    _print_table_from_dicts(headers, row_dicts)

def print_same_interface_entries(conn, limit=50):
    print(f"\n--- Top {limit} Same-Interface Connections by Bytes Transferred (Descending, no ID) ---")
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            protocol, interface1, ip_addr1, port1, xlated_ip1, xlated_port1,
            ip_addr2, port2, xlated_ip2, xlated_port2,
            bytes_transferred, idle_time, uptime, flags
        FROM
            connections
        WHERE
            interface1 = interface2
        ORDER BY
            bytes_transferred DESC, id DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()

    row_dicts = []
    for (proto, interface, ip1, port1, xip1, xport1,
         ip2, port2, xip2, xport2,
         bytes_t, idle, uptime_val, flags) in rows:

        ip1_port = f"{ip1}:{port1}" if port1 else (ip1 or "")
        ip2_port = f"{ip2}:{port2}" if port2 else (ip2 or "")
        xip1_port = f"{xip1}:{xport1}" if xip1 and xport1 else (xip1 or "")
        xip2_port = f"{xip2}:{xport2}" if xip2 and xport2 else (xip2 or "")

        row_dicts.append({
            "PROTO": proto,
            "IFACE": interface,
            "BYTES": bytes_t,
            "IP1:PORT1": ip1_port,
            "X-IP1:X-PORT1": xip1_port,
            "IP2:PORT2": ip2_port,
            "X-IP2:X-PORT2": xip2_port,
            "IDLE": idle or "",
            "UPTIME": uptime_val or "",
            "FLAGS": flags or "",
        })

    headers = ["PROTO", "IFACE", "BYTES", "IP1:PORT1", "X-IP1:X-PORT1",
               "IP2:PORT2", "X-IP2:X-PORT2", "IDLE", "UPTIME", "FLAGS"]
    headers = _filter_columns(headers, row_dicts)
    _print_table_from_dicts(headers, row_dicts)

def print_top_flag_n_entries(conn, limit=50):
    print(f"\n--- Top {limit} Connections with Flag 'N' by Bytes Transferred (Descending, no ID) ---")
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            protocol, interface1, ip_addr1, port1, xlated_ip1, xlated_port1,
            ip_addr2, port2, xlated_ip2, xlated_port2,
            bytes_transferred, idle_time, uptime, flags
        FROM
            connections
        WHERE
            flags LIKE '%N%' OR flags LIKE '%n%'
        ORDER BY
            bytes_transferred DESC, id DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()

    row_dicts = []
    for (proto, interface1, ip1, port1, xip1, xport1,
         ip2, port2, xip2, xport2,
         bytes_t, idle, uptime_val, flags) in rows:

        ip1_port = f"{ip1}:{port1}" if port1 else (ip1 or "")
        ip2_port = f"{ip2}:{port2}" if port2 else (ip2 or "")
        xip1_port = f"{xip1}:{xport1}" if xip1 and xport1 else (xip1 or "")
        xip2_port = f"{xip2}:{xport2}" if xip2 and xport2 else (xip2 or "")

        row_dicts.append({
            "PROTO": proto,
            "IFACE1": interface1,
            "BYTES": bytes_t,
            "IP1:PORT1": ip1_port,
            "X-IP1:X-PORT1": xip1_port,
            "IP2:PORT2": ip2_port,
            "X-IP2:X-PORT2": xip2_port,
            "IDLE": idle or "",
            "UPTIME": uptime_val or "",
            "FLAGS": flags or "",
        })

    headers = ["PROTO", "IFACE1", "BYTES", "IP1:PORT1", "X-IP1:X-PORT1",
               "IP2:PORT2", "X-IP2:X-PORT2", "IDLE", "UPTIME", "FLAGS"]
    headers = _filter_columns(headers, row_dicts)
    _print_table_from_dicts(headers, row_dicts)

def print_ip_counts(conn, limit=50):
    print(f"\n--- IP Address Counts (Descending, Top {limit}) ---")
    cursor = conn.cursor()

    cursor.execute('''
        SELECT ip_addr, COUNT(*) as count
        FROM (
            SELECT ip_addr1 as ip_addr FROM connections
            UNION ALL
            SELECT ip_addr2 as ip_addr FROM connections
            UNION ALL
            SELECT xlated_ip1 as ip_addr FROM connections WHERE xlated_ip1 IS NOT NULL
            UNION ALL
            SELECT xlated_ip2 as ip_addr FROM connections WHERE xlated_ip2 IS NOT NULL
            UNION ALL
            SELECT initiator_ip as ip_addr FROM connections WHERE initiator_ip IS NOT NULL
            UNION ALL
            SELECT responder_ip as ip_addr FROM connections WHERE responder_ip IS NOT NULL
        )
        GROUP BY ip_addr
        ORDER BY count DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()

    row_dicts = [{"IP ADDRESS": ip, "COUNT": count} for ip, count in rows]
    headers = ["IP ADDRESS", "COUNT"]
    headers = _filter_columns(headers, row_dicts)
    _print_table_from_dicts(headers, row_dicts)

def print_port_counts(conn, limit=50):
    print(f"\n--- Port Counts (Descending, Top {limit}) ---")
    cursor = conn.cursor()

    cursor.execute('''
        SELECT port, COUNT(*) as count
        FROM (
            SELECT port1 as port FROM connections
            UNION ALL
            SELECT port2 as port FROM connections
            UNION ALL
            SELECT xlated_port1 as port FROM connections WHERE xlated_port1 IS NOT NULL
            UNION ALL
            SELECT xlated_port2 as port FROM connections WHERE xlated_port2 IS NOT NULL
        )
        WHERE port IS NOT NULL AND port != 0
        GROUP BY port
        ORDER BY count DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()

    row_dicts = [{"PORT": port, "COUNT": count} for port, count in rows]
    headers = ["PORT", "COUNT"]
    headers = _filter_columns(headers, row_dicts)
    _print_table_from_dicts(headers, row_dicts)

def print_top_initiators(conn, limit=50):
    print(f"\n--- Top {limit} Initiator IPs by Connection Count ---")
    cursor = conn.cursor()

    cursor.execute('''
        SELECT initiator_ip, COUNT(*) as count
        FROM connections
        WHERE initiator_ip IS NOT NULL
        GROUP BY initiator_ip
        ORDER BY count DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()

    row_dicts = [{"INITIATOR IP": ip, "COUNT": count} for ip, count in rows]
    headers = ["INITIATOR IP", "COUNT"]
    headers = _filter_columns(headers, row_dicts)
    _print_table_from_dicts(headers, row_dicts)

def print_top_responders(conn, limit=50):
    print(f"\n--- Top {limit} Responder IPs by Connection Count ---")
    cursor = conn.cursor()

    cursor.execute('''
        SELECT responder_ip, COUNT(*) as count
        FROM connections
        WHERE responder_ip IS NOT NULL
        GROUP BY responder_ip
        ORDER BY count DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()

    row_dicts = [{"RESPONDER IP": ip, "COUNT": count} for ip, count in rows]
    headers = ["RESPONDER IP", "COUNT"]
    headers = _filter_columns(headers, row_dicts)
    _print_table_from_dicts(headers, row_dicts)

def print_top_initiators_with_n_flag(conn, limit=50):
    print(f"\n--- Top {limit} Initiator IPs (Flags containing 'N') ---")
    cursor = conn.cursor()

    cursor.execute('''
        SELECT initiator_ip, COUNT(*) as count
        FROM connections
        WHERE initiator_ip IS NOT NULL AND (flags LIKE '%N%' OR flags LIKE '%n%')
        GROUP BY initiator_ip
        ORDER BY count DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()

    row_dicts = [{"INITIATOR IP": ip, "N-FLAG COUNT": count} for ip, count in rows]
    headers = ["INITIATOR IP", "N-FLAG COUNT"]
    headers = _filter_columns(headers, row_dicts)
    _print_table_from_dicts(headers, row_dicts)

def print_top_responders_with_n_flag(conn, limit=50):
    print(f"\n--- Top {limit} Responder IPs (Flags containing 'N') ---")
    cursor = conn.cursor()

    cursor.execute('''
        SELECT responder_ip, COUNT(*) as count
        FROM connections
        WHERE responder_ip IS NOT NULL AND (flags LIKE '%N%' OR flags LIKE '%n%')
        GROUP BY responder_ip
        ORDER BY count DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()

    row_dicts = [{"RESPONDER IP": ip, "N-FLAG COUNT": count} for ip, count in rows]
    headers = ["RESPONDER IP", "N-FLAG COUNT"]
    headers = _filter_columns(headers, row_dicts)
    _print_table_from_dicts(headers, row_dicts)


# --- LLM INTEGRATION FUNCTIONS ---

def query_llm_for_sql(user_query: str) -> Optional[str]:
    global GEMINI_API_KEY

    if not GEMINI_API_KEY:
        print("[!] LLM API key is missing. Cannot process natural language query.")
        return None

    print(f"[*] Debug Check: API Key is loaded (Length: {len(GEMINI_API_KEY)} chars).")

    system_instruction = (
        "You are an expert SQLite SQL query generator. Your task is to convert a user's natural "
        "language request into a single, executable SQLite SQL query for a table named 'connections'. "
        "Do not include any text, explanations, or formatting (like markdown quotes or SQL comments) "
        "outside of the raw SQL query itself. Always use appropriate aggregation (COUNT, SUM) and "
        "ORDER BY/LIMIT clauses when the user asks for 'top' items. "
        "Use the following schema exactly:\n\n"
        "CREATE TABLE connections (\n"
        "    id INTEGER PRIMARY KEY, protocol TEXT, interface1 TEXT, ip_addr1 TEXT, port1 INTEGER,\n"
        "    xlated_ip1 TEXT, xlated_port1 INTEGER,\n"
        "    interface2 TEXT, ip_addr2 TEXT, port2 INTEGER,\n"
        "    xlated_ip2 TEXT, xlated_port2 INTEGER,\n"
        "    idle_time TEXT, uptime TEXT, bytes_transferred INTEGER,\n"
        "    flags TEXT, initiator_ip TEXT, responder_ip TEXT\n"
        ")"
    )

    payload = {
        "contents": [{"parts": [{"text": user_query}]}],
        "systemInstruction": {"parts": [{"text": system_instruction}]},
        "generationConfig": {
            "temperature": 0.0,
            "maxOutputTokens": 500
        }
    }

    headers = {'Content-Type': 'application/json'}

    max_retries = 5
    base_delay = 1

    for attempt in range(max_retries):
        try:
            print("[*] Sending query to LLM...")

            response = requests.post(
                f"{LLM_API_URL}?key={GEMINI_API_KEY}",
                headers=headers,
                data=json.dumps(payload)
            )

            response.raise_for_status()
            result = response.json()

            if 'candidates' not in result or not result['candidates']:
                print(f"[!!!] LLM did not return any candidates (Attempt {attempt + 1}/{max_retries}).")
                print(f"      Full LLM Response for debugging: {json.dumps(result, indent=2)}")
                if 'promptFeedback' in result and 'safetyRatings' in result['promptFeedback']:
                    print("      Safety Feedback:")
                    for rating in result['promptFeedback']['safetyRatings']:
                        print(f"        Category: {rating['category']}, Probability: {rating['probability']}")
                return None

            if 'content' not in result['candidates'][0] or 'parts' not in result['candidates'][0]['content']:
                print(f"[!!!] LLM candidate content structure unexpected (Attempt {attempt + 1}/{max_retries}).")
                print(f"      Full LLM Response for debugging: {json.dumps(result, indent=2)}")
                return None

            sql_query = result['candidates'][0]['content']['parts'][0]['text'].strip()
            return sql_query

        except requests.exceptions.HTTPError as e:
            print(f"[!] HTTP Error during LLM query (Attempt {attempt + 1}/{max_retries}): {e}")
            if response.status_code == 400:
                print(f"[!!!] BAD REQUEST (400) - Detailed error response received.")
                print(f"      Response Text for debugging (Crucial): {response.text}")
                return None
            if response.status_code == 403:
                print(f"[!!!] FORBIDDEN (403): The API key might lack permissions or the model is not available.")
        except requests.exceptions.RequestException as e:
            print(f"[!] Request Error during LLM query (Attempt {attempt + 1}/{max_retries}): {e}")
        except (KeyError, IndexError) as e:
            print(f"[!] Parsing Error: LLM response structure unexpected (Attempt {attempt + 1}/{max_retries}): {e}")
            if 'result' in locals():
                print(f"      Full LLM Response at time of KeyError: {json.dumps(result, indent=2)}")

        if attempt < max_retries - 1:
            delay = base_delay * (2 ** attempt)
            time.sleep(delay)

    print("[!] Failed to get a valid response from the LLM after multiple retries.")
    return None

def execute_llm_sql(conn: sqlite3.Connection, sql_query: str):
    """
    Executes the generated SQL query and prints the results in a formatted table,
    hiding any columns that are entirely blank (per _is_blank definition).
    """
    try:
        cursor = conn.cursor()
        cursor.execute(sql_query)
        results = cursor.fetchall()
        if cursor.description is None:
            print("\n[!] Query executed successfully, but no columns were returned.")
            return

        col_names = [d[0] for d in cursor.description]

        # Build list of row dicts
        row_dicts = []
        for row in results:
            rd = {col_names[i]: row[i] for i in range(len(col_names))}
            row_dicts.append(rd)

        # Filter headers
        headers = _filter_columns(col_names, row_dicts)

        print("\n--- LLM QUERY RESULT ---")
        _print_table_from_dicts(headers, row_dicts)
        print(f"[*] Query executed: {sql_query}")
        print(f"[*] Total rows returned: {len(results)}\n")

    except sqlite3.OperationalError as e:
        print(f"\n[!] SQL Execution Error: The generated query failed due to an operational error.")
        print(f"    Error details: {e}")
        print(f"    Failing query: {sql_query}\n")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred during SQL execution: {e}\n")


# --- MAIN EXECUTION ---

def cleanup():
    print("\n[*] Cleanup skipped as requested. Database and input file retained.")

def main():
    input_file_path = None

    if len(sys.argv) > 1:
        input_file_path = sys.argv[1]
        print(f"[*] Using input file from command line: {input_file_path}")
    else:
        while True:
            user_input = input("Please enter the path to the ASA connection log file (or press Enter to exit): ").strip()
            if user_input:
                input_file_path = user_input
                print(f"[*] Using input file from user prompt: {input_file_path}")
                break
            else:
                print("[!] No input file provided. Exiting.")
                sys.exit(0)

    conn = init_db()
    process_file(conn, input_file_path)

    print("\n\n========================================================")
    print("      INITIAL LOG ANALYSIS REPORTS        ")
    print("========================================================")

    print_top_bytes_entries(conn)
    print_top_idle_time_entries(conn)
    print_top_uptime_entries(conn)
    print_same_interface_entries(conn)
    print_top_flag_n_entries(conn)
    print_top_initiators(conn)
    print_top_responders(conn)
    print_top_initiators_with_n_flag(conn)
    print_top_responders_with_n_flag(conn)
    print_ip_counts(conn, 50)
    print_port_counts(conn, 50)

    print("\n========================================================")
    print("      NATURAL LANGUAGE DATABASE QUERY INTERFACE        ")
    print("========================================================")

    if not GEMINI_API_KEY:
        print("[!] LLM interface disabled because GEMINI_API_KEY is missing.")
        print("    Please set the environment variable and rerun the script.")
    else:
        print("[*] LLM interface is active.")
        print("You can now ask questions about the data using natural language.")
        print("Try queries like: 'show me the top 10 protocols by count',")
        print("or 'list all connections where the initiator is 192.168.2.20'.")
        print("Type 'exit' or 'quit' to end the session.")

        while True:
            try:
                user_input = input("Query > ").strip()

                if user_input.lower() in ['exit', 'quit']:
                    print("\nSession ended. Goodbye!")
                    break

                if not user_input:
                    continue

                sql_query = query_llm_for_sql(user_input)

                if sql_query:
                    execute_llm_sql(conn, sql_query)

            except EOFError:
                print("\nSession ended. Goodbye!")
                break
            except Exception as e:
                print(f"\n[!] An unhandled error occurred in the loop: {e}")
                break

    conn.close()
    cleanup()

if __name__ == "__main__":
    main()
