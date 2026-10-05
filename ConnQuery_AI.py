import sqlite3
import os
import sys
import re
import json
import time
import base64
from typing import List, Tuple, Optional, Dict, Any
from io import StringIO # Import StringIO to capture print output

# --- DEPENDENCY IMPORTS ---
try:
    import requests
except ImportError:
    print("[!] The 'requests' library is not installed. Please install it (pip install requests).")
    sys.exit(1)


# --- CONFIGURATION ---
DB_NAME = 'asa_connections.db'
BATCH_SIZE = 5000

# Choose your model (gpt-4o, gpt-5-nano, etc.)
LLM_MODEL = 'gpt-5-nano' 

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
        value = str(value) # Convert numeric 0 to string "0" for comparison below
    s = str(value).strip()
    return s == "" or s.upper() == "NULL" or s == "-" or s == "0" # Also consider "0" as blank


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
            responder_ip TEXT,
            forward_current_rate INTEGER,
            reverse_current_rate INTEGER,
            forward_max_rate INTEGER,
            reverse_max_rate INTEGER,
            forward_time_last_max TEXT,
            reverse_time_last_max TEXT
        )
    ''')
    conn.commit()
    print("\n--- DATABASE SCHEMA FOR LLM CONTEXT ---")
    print(
        "TABLE: connections (\n"
        "  id INTEGER PRIMARY KEY, protocol TEXT, interface1 TEXT, ip_addr1 TEXT, port1 INTEGER,\n"
        "  xlated_ip1 TEXT, xlated_port1 INTEGER, interface2 TEXT, ip_addr2 TEXT, port2 INTEGER,\n"
        "  xlated_ip2 TEXT, xlated_port2 INTEGER, idle_time TEXT, uptime TEXT, bytes_transferred INTEGER,\n"
        "  flags TEXT, initiator_ip TEXT, responder_ip TEXT,\n"
        "  forward_current_rate INTEGER, reverse_current_rate INTEGER, forward_max_rate INTEGER,\n"
        "  reverse_max_rate INTEGER, forward_time_last_max TEXT, reverse_time_last_max TEXT\n"
        ")\n"
    )
    print("------------------------------------------")
    return conn

def _time_to_seconds(time_str: str) -> int:
    if not time_str:
        return 0

    time_str = re.sub(r'\s+', '', time_str).strip()

    if ':' in time_str:
        parts = [int(p) for p in time_str.split(':')]
        if len(parts) == 3:
            return parts[0] * 3600 + parts[1] * 60 + parts[2]
        elif len(parts) == 2:
            return parts[0] * 60 + parts[1]
        return 0

    total_seconds = 0
    m_match = re.search(r'(\d+)m', time_str)
    if m_match: total_seconds += int(m_match.group(1)) * 60
    s_match = re.search(r'(\d+)s', time_str)
    if s_match: total_seconds += int(s_match.group(1))
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
        r'(\w+)\s+([a-zA-Z0-9_-]+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)\s+([a-zA-Z0-9_-]+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+),\s*idle\s+([\d\s:]+),\s*bytes\s+(\d+),\s*flags\s+([^\s,]+)',
        line
    )
    if not match: return None
    try:
        protocol, int1, ip1_raw, int2, ip2_raw, idle_time_raw, bytes_val_str, flags = match.groups()
        idle_time = re.sub(r'\s+', '', idle_time_raw).strip()
        def parse_ip_port_colon(ip_port_str):
            try:
                ip, port_str = ip_port_str.rsplit(':', 1)
                return ip, int(port_str)
            except ValueError:
                return ip_port_str, 0
        ip_addr1, port1 = parse_ip_port_colon(ip1_raw)
        ip_addr2, port2 = parse_ip_port_colon(ip2_raw)
        return (
            protocol, int1, ip_addr1, port1, None, None, int2, ip_addr2, port2, None, None,
            idle_time, None, int(bytes_val_str), flags, None, None, None, None, None, None, None, None
        )
    except Exception as e:
        print(f"[!] Format 1 Parsing Error on line: {line.strip()}. Error: {e}")
        return None

def _parse_format2_record(full_record: str) -> Optional[Tuple[Any, ...]]:
    main_match = re.search(r'^(UDP|TCP|ICMP|IP)\s+(\S+):\s*([\d\.]+/\d+)\s+(\S+):\s*([\d\.]+/\d+)', full_record)
    if not main_match:
        main_match = re.search(r'^(UDP|TCP|ICMP|IP)\s+(\S+):\s*([^,\s]+)\s+(\S+):\s*([^,\s]+)', full_record)
        if not main_match: return None
    protocol = main_match.group(1)
    int1 = main_match.group(2).replace(':', '')
    ip1_raw = main_match.group(3)
    int2 = main_match.group(4).replace(':', '')
    ip2_raw = main_match.group(5)
    ip_addr1, port1 = _parse_ip_port_slash(ip1_raw)
    ip_addr2, port2 = _parse_ip_port_slash(ip2_raw)
    flags_match = re.search(r'flags\s+-?\s*([^\s,]+)', full_record)
    flags = flags_match.group(1).strip() if flags_match else ""
    idle_match = re.search(r'idle\s+([^\s,]+)', full_record)
    idle_time = idle_match.group(1).strip() if idle_match else ""
    uptime_match = re.search(r'uptime\s+([^\s,]+)', full_record)
    uptime = uptime_match.group(1).strip() if uptime_match else None
    bytes_match = re.search(r'bytes\s+(\d+)', full_record)
    bytes_val = int(bytes_match.group(1)) if bytes_match else 0
    init_resp_match = re.search(r'Initiator:\s*([^,\s]+),\s*Responder:\s*([^,\s]+)', full_record)
    initiator_ip = init_resp_match.group(1) if init_resp_match else None
    responder_ip = init_resp_match.group(2) if init_resp_match else None
    return (
        protocol, int1, ip_addr1, port1, None, None, int2, ip_addr2, port2, None, None,
        idle_time, uptime, bytes_val, flags, initiator_ip, responder_ip, None, None, None, None, None, None
    )

def _parse_format3_line(full_record: str) -> Optional[Tuple[Any, ...]]:
    main_regex = re.compile(
        r'^(UDP|TCP|ICMP|IP)\s+([^:\s]+):\s*([^/\s]+/[\d\.]+)\s*\(([^/\s]+/[\d\.]+)\)\s*'
        r'([^:\s]+):\s*([^/\s]+/[\d\.]+)\s*\(([^/\s]+/[\d\.]+)\)'
    )
    main_match = main_regex.search(full_record)
    if not main_match: return None
    try:
        protocol, int1, ip1_raw, xip1_raw, int2, ip2_raw, xip2_raw = main_match.groups()
        ip_addr1, port1 = _parse_ip_port_slash(ip1_raw)
        ip_addr2, port2 = _parse_ip_port_slash(ip2_raw)
        xlated_ip1, xlated_port1 = _parse_ip_port_slash(xip1_raw)
        xlated_ip2, xlated_port2 = _parse_ip_port_slash(xip2_raw)
        flags_match = re.search(r'flags\s+-?\s*([^\s,]+)', full_record)
        flags = flags_match.group(1).strip() if flags_match else ""
        idle_match = re.search(r'idle\s+([^\s,]+)', full_record)
        idle_time = idle_match.group(1).strip() if idle_match else ""
        uptime_match = re.search(r'uptime\s+([^\s,]+)', full_record)
        uptime = uptime_match.group(1).strip() if uptime_match else None
        bytes_match = re.search(r'bytes\s+(\d+)', full_record)
        bytes_val = int(bytes_match.group(1)) if bytes_match else 0
        init_resp_match = re.search(r'Initiator:\s*([^,\s]+),\s*Responder:\s*([^,\s]+)', full_record)
        initiator_ip = init_resp_match.group(1) if init_resp_match else None
        responder_ip = init_resp_match.group(2) if init_resp_match else None
        return (
            protocol, int1, ip_addr1, port1, xlated_ip1, xlated_port1,
            int2, ip_addr2, port2, xlated_ip2, xlated_port2,
            idle_time, uptime, bytes_val, flags, initiator_ip, responder_ip,
            None, None, None, None, None, None
        )
    except Exception as e:
        print(f"[!] Format 3 Internal Parsing Error: {e}")
        return None

def _parse_format4_record(record_lines: List[str]) -> Optional[Tuple[Any, ...]]:
    if not record_lines: return None
    full_record_text = ' '.join(line.strip() for line in record_lines)
    try:
        main_match = re.search(r'^(UDP|TCP|ICMP|IP)\s+(\S+):\s*([\d\.]+/\d+)\s+(\S+):\s*([\d\.]+/\d+)', record_lines[0])
        if not main_match: return None
        protocol = main_match.group(1)
        int1 = main_match.group(2).replace(':', '')
        ip1_raw = main_match.group(3)
        int2 = main_match.group(4).replace(':', '')
        ip2_raw = main_match.group(5)
        ip_addr1, port1 = _parse_ip_port_slash(ip1_raw)
        ip_addr2, port2 = _parse_ip_port_slash(ip2_raw)
        flags_match = re.search(r'flags\s+-?\s*([^\s,]+)', full_record_text)
        flags = flags_match.group(1).strip() if flags_match else ""
        idle_match = re.search(r'idle\s+([^\s,]+)', full_record_text)
        idle_time = idle_match.group(1).strip() if idle_match else ""
        uptime_match = re.search(r'uptime\s+([^\s,]+)', full_record_text)
        uptime = uptime_match.group(1).strip() if uptime_match else None
        bytes_match = re.search(r'bytes\s+(\d+)', full_record_text)
        bytes_val = int(bytes_match.group(1)) if bytes_match else 0
        init_resp_match = re.search(r'Initiator:\s*([^,\s]+),\s*Responder:\s*([^,\s]+)', full_record_text)
        initiator_ip = init_resp_match.group(1) if init_resp_match else None
        responder_ip = init_resp_match.group(2) if init_resp_match else None
        current_rate_match = re.search(r'current rate:\s*(\d+)/(\d+)', full_record_text)
        forward_current_rate = int(current_rate_match.group(1)) if current_rate_match else None
        reverse_current_rate = int(current_rate_match.group(2)) if current_rate_match else None
        max_rate_match = re.search(r'max rate:\s*(\d+)/(\d+)', full_record_text)
        forward_max_rate = int(max_rate_match.group(1)) if max_rate_match else None
        reverse_max_rate = int(max_rate_match.group(2)) if max_rate_match else None
        time_last_max_match = re.search(r'time since last max\s+([^\s/]+)/([^\s/]+)', full_record_text)
        forward_time_last_max = time_last_max_match.group(1).strip() if time_last_max_match else None
        reverse_time_last_max = time_last_max_match.group(2).strip() if time_last_max_match else None
        return (
            protocol, int1, ip_addr1, port1, None, None, int2, ip_addr2, port2, None, None,
            idle_time, uptime, bytes_val, flags, initiator_ip, responder_ip,
            forward_current_rate, reverse_current_rate, forward_max_rate, reverse_max_rate,
            forward_time_last_max, reverse_time_last_max
        )
    except Exception as e:
        print(f"[!] Format 4 Internal Parsing Error: {e}")
        return None

def _parse_format5_record(record_lines: List[str]) -> Optional[Tuple[Any, ...]]:
    if not record_lines: return None
    full_record_text = ' '.join(line.strip() for line in record_lines)
    try:
        main_regex = re.compile(
            r'^(UDP|TCP|ICMP|IP)\s+([^:\s]+):\s*([^/\s]+/[\d\.]+)\s*\(([^/\s]+/[\d\.]+)\)\s*'
            r'([^:\s]+):\s*([^/\s]+/[\d\.]+)\s*\(([^/\s]+/[\d\.]+)\)'
        )
        main_match = main_regex.search(record_lines[0])
        if not main_match: return None
        protocol, int1, ip1_raw, xip1_raw, int2, ip2_raw, xip2_raw = main_match.groups()
        ip_addr1, port1 = _parse_ip_port_slash(ip1_raw)
        ip_addr2, port2 = _parse_ip_port_slash(ip2_raw)
        xlated_ip1, xlated_port1 = _parse_ip_port_slash(xip1_raw)
        xlated_ip2, xlated_port2 = _parse_ip_port_slash(xip2_raw)
        flags_match = re.search(r'flags\s+-?\s*([^\s,]+)', full_record_text)
        flags = flags_match.group(1).strip() if flags_match else ""
        idle_match = re.search(r'idle\s+([^\s,]+)', full_record_text)
        idle_time = idle_match.group(1).strip() if idle_match else ""
        uptime_match = re.search(r'uptime\s+([^\s,]+)', full_record_text)
        uptime = uptime_match.group(1).strip() if uptime_match else None
        bytes_match = re.search(r'bytes\s+(\d+)', full_record_text)
        bytes_val = int(bytes_match.group(1)) if bytes_match else 0
        init_resp_match = re.search(r'Initiator:\s*([^,\s]+),\s*Responder:\s*([^,\s]+)', full_record_text)
        initiator_ip = init_resp_match.group(1) if init_resp_match else None
        responder_ip = init_resp_match.group(2) if init_resp_match else None
        current_rate_match = re.search(r'current rate:\s*(\d+)/(\d+)', full_record_text)
        forward_current_rate = int(current_rate_match.group(1)) if current_rate_match else None
        reverse_current_rate = int(current_rate_match.group(2)) if current_rate_match else None
        max_rate_match = re.search(r'max rate:\s*(\d+)/(\d+)', full_record_text)
        forward_max_rate = int(max_rate_match.group(1)) if max_rate_match else None
        reverse_max_rate = int(max_rate_match.group(2)) if max_rate_match else None
        time_last_max_match = re.search(r'time since last max\s+([^\s/]+)/([^\s/]+)', full_record_text)
        forward_time_last_max = time_last_max_match.group(1).strip() if time_last_max_match else None
        reverse_time_last_max = time_last_max_match.group(2).strip() if time_last_max_match else None
        return (
            protocol, int1, ip_addr1, port1, xlated_ip1, xlated_port1,
            int2, ip_addr2, port2, xlated_ip2, xlated_port2,
            idle_time, uptime, bytes_val, flags, initiator_ip, responder_ip,
            forward_current_rate, reverse_current_rate, forward_max_rate, reverse_max_rate,
            forward_time_last_max, reverse_time_last_max
        )
    except Exception as e:
        print(f"[!] Format 5 Internal Parsing Error: {e}")
        return None

def process_file(conn: sqlite3.Connection, filename: str) -> Optional[int]:
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

        start_processing_index = 0
        has_data_rate = any('data-rate forward/reverse' in line for line in lines)
        xlate_pattern_re = re.compile(r'^(UDP|TCP|ICMP|IP)\s+\S+:\s*[^(\s]+/\d+\s+\([^)]+\)')
        has_xlate_pattern = any(xlate_pattern_re.search(line) for line in lines)

        if has_data_rate and has_xlate_pattern: format_type = 5
        elif has_data_rate: format_type = 4
        elif has_xlate_pattern: format_type = 3
        else:
            for idx, line in enumerate(lines):
                stripped_line = line.strip()
                if not stripped_line: continue
                if re.search(r'^(UDP|TCP|ICMP|IP)\s+([a-zA-Z0-9_-]+)\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\s+([a-zA-Z0-9_-]+)\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+,\s*idle\s+([\d\s:]+)', stripped_line):
                    format_type = 1
                    start_processing_index = idx
                    break
                elif re.search(r'^(UDP|TCP|ICMP|IP)\s+\S+:\s+\d{1,3}(?:\.\d{1,3}){3}/\d+', stripped_line):
                    format_type = 2
                    start_processing_index = idx
                    break
        
        if format_type is None: 
            print("[!] Error: Could not determine log format from the file content.")
            return None

        print(f"[*] Detected format: Format {format_type}")
        i = start_processing_index
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1
                continue
            record_data = None
            record_block = []

            if format_type in (4, 5):
                if line.startswith(('UDP', 'TCP', 'ICMP', 'IP')):
                    record_block.append(line)
                    j = i + 1
                    while j < len(lines) and lines[j].strip() and (lines[j].startswith((' ', '\t')) or 'Initiator:' in lines[j] or 'data-rate' in lines[j]):
                        record_block.append(lines[j])
                        j += 1
                    if format_type == 5: record_data = _parse_format5_record(record_block)
                    else: record_data = _parse_format4_record(record_block)
                    i = j
                else:
                    i += 1
            elif format_type == 3:
                full_record = line
                if i + 1 < len(lines) and lines[i+1].strip().startswith('Initiator:'):
                    full_record += " " + lines[i+1].strip()
                    i += 1
                record_data = _parse_format3_line(full_record)
                i += 1
            elif format_type == 2:
                full_record = line
                if i + 1 < len(lines) and lines[i+1].startswith((' ', '\t')) and ('flags' in lines[i+1] or 'bytes' in lines[i+1]):
                    full_record += " " + lines[i+1].strip()
                    i += 1
                if i + 1 < len(lines) and lines[i+1].strip().startswith('Initiator:'):
                    full_record += " " + lines[i+1].strip()
                    i += 1
                record_data = _parse_format2_record(full_record)
                i += 1
            elif format_type == 1:
                full_record = line
                record_data = _parse_format1_line(full_record)
                i += 1
            else:
                i += 1
                continue

            if record_data and len(record_data) == 23:
                data_batch.append(record_data)
                total_processed += 1

            if len(data_batch) >= BATCH_SIZE:
                cursor.executemany('''
                    INSERT INTO connections (
                        protocol, interface1, ip_addr1, port1, xlated_ip1, xlated_port1,
                        interface2, ip_addr2, port2, xlated_ip2, xlated_port2,
                        idle_time, uptime, bytes_transferred, flags, initiator_ip, responder_ip,
                        forward_current_rate, reverse_current_rate, forward_max_rate,
                        reverse_max_rate, forward_time_last_max, reverse_time_last_max
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', data_batch)
                conn.commit()
                data_batch = []

        if data_batch:
            cursor.executemany('''
                INSERT INTO connections (
                    protocol, interface1, ip_addr1, port1, xlated_ip1, xlated_port1,
                    interface2, ip_addr2, port2, xlated_ip2, xlated_port2,
                    idle_time, uptime, bytes_transferred, flags, initiator_ip, responder_ip,
                    forward_current_rate, reverse_current_rate, forward_max_rate,
                    reverse_max_rate, forward_time_last_max, reverse_time_last_max
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', data_batch)
            conn.commit()

        print(f"[*] Successfully processed {total_processed} entries from {filename} into database.")
        return format_type
    except Exception as e:
        print(f"[!] An unexpected error occurred during file processing: {e}")
        sys.exit(1)


# --- REPORTING FUNCTIONS ---
# (Keeping reporting functions exactly as they were in the original script)

def print_top_bytes_entries(conn, limit=50):
    print(f"\n--- Top {limit} Connections by Bytes Transferred (Descending) ---")
    cursor = conn.cursor()
    cursor.execute('''
        SELECT protocol, interface1, ip_addr1, port1, xlated_ip1, xlated_port1,
               interface2, ip_addr2, port2, xlated_ip2, xlated_port2,
               bytes_transferred, idle_time, uptime, flags, initiator_ip, responder_ip
        FROM connections ORDER BY bytes_transferred DESC, id DESC LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    row_dicts = []
    for (proto, int1, ip1, p1, xip1, xp1, int2, ip2, p2, xip2, xp2, bt, idle, up, flg, init, resp) in rows:
        row_dicts.append({
            "PROTO": proto, "BYTES": bt, "IFACE1": int1, 
            "IP1:PORT1": f"{ip1}:{p1}" if p1 else ip1, 
            "IFACE2": int2, "IP2:PORT2": f"{ip2}:{p2}" if p2 else ip2, 
            "IDLE": idle or "", "UPTIME": up or "", "FLAGS": flg or ""
        })
    headers = ["PROTO", "BYTES", "IFACE1", "IP1:PORT1", "IFACE2", "IP2:PORT2", "IDLE", "UPTIME", "FLAGS"]
    _print_table_from_dicts(_filter_columns(headers, row_dicts), row_dicts)

def print_top_idle_time_entries(conn, limit=50):
    print(f"\n--- Top {limit} Connections by Idle Time (Descending) ---")
    cursor = conn.cursor()
    cursor.execute('''SELECT protocol, interface1, ip_addr1, port1, interface2, ip_addr2, port2, idle_time, uptime, bytes_transferred, flags FROM connections''')
    sorted_rows = sorted(cursor.fetchall(), key=lambda r: _time_to_seconds(r[7] or "0s"), reverse=True)[:limit]
    row_dicts = [{"PROTO": r[0], "IDLE": r[7] or "", "IFACE1": r[1], "IP1:PORT1": f"{r[2]}:{r[3]}" if r[3] else r[2], "IFACE2": r[4], "IP2:PORT2": f"{r[5]}:{r[6]}" if r[6] else r[5], "BYTES": r[9], "FLAGS": r[10] or ""} for r in sorted_rows]
    _print_table_from_dicts(_filter_columns(["PROTO", "IDLE", "IFACE1", "IP1:PORT1", "IFACE2", "IP2:PORT2", "BYTES", "FLAGS"], row_dicts), row_dicts)

def print_top_uptime_entries(conn, limit=50):
    print(f"\n--- Top {limit} Connections by Uptime (Descending) ---")
    cursor = conn.cursor()
    cursor.execute('''SELECT protocol, interface1, ip_addr1, port1, interface2, ip_addr2, port2, idle_time, uptime, bytes_transferred, flags FROM connections''')
    sorted_rows = sorted(cursor.fetchall(), key=lambda r: _time_to_seconds(r[8] or "0s"), reverse=True)[:limit]
    row_dicts = [{"PROTO": r[0], "UPTIME": r[8] or "", "IFACE1": r[1], "IP1:PORT1": f"{r[2]}:{r[3]}" if r[3] else r[2], "IFACE2": r[4], "IP2:PORT2": f"{r[5]}:{r[6]}" if r[6] else r[5], "BYTES": r[9], "FLAGS": r[10] or ""} for r in sorted_rows]
    _print_table_from_dicts(_filter_columns(["PROTO", "UPTIME", "IFACE1", "IP1:PORT1", "IFACE2", "IP2:PORT2", "BYTES", "FLAGS"], row_dicts), row_dicts)

def print_same_interface_entries(conn, limit=50):
    print(f"\n--- Top {limit} Same-Interface Connections by Bytes Transferred ---")
    cursor = conn.cursor()
    cursor.execute('''SELECT protocol, interface1, ip_addr1, port1, ip_addr2, port2, bytes_transferred, idle_time, flags FROM connections WHERE interface1 = interface2 ORDER BY bytes_transferred DESC LIMIT ?''', (limit,))
    row_dicts = [{"PROTO": r[0], "IFACE": r[1], "BYTES": r[6], "IP1:PORT1": f"{r[2]}:{r[3]}" if r[3] else r[2], "IP2:PORT2": f"{r[4]}:{r[5]}" if r[5] else r[4], "IDLE": r[7] or "", "FLAGS": r[8] or ""} for r in cursor.fetchall()]
    _print_table_from_dicts(_filter_columns(["PROTO", "IFACE", "BYTES", "IP1:PORT1", "IP2:PORT2", "IDLE", "FLAGS"], row_dicts), row_dicts)

def print_top_flag_n_entries(conn, limit=50):
    print(f"\n--- Top {limit} Connections with Flag 'N' by Bytes Transferred ---")
    cursor = conn.cursor()
    cursor.execute('''SELECT protocol, interface1, ip_addr1, port1, interface2, ip_addr2, port2, bytes_transferred, flags FROM connections WHERE flags LIKE '%N%' OR flags LIKE '%n%' ORDER BY bytes_transferred DESC LIMIT ?''', (limit,))
    row_dicts = [{"PROTO": r[0], "IFACE1": r[1], "IFACE2": r[4], "BYTES": r[7], "IP1:PORT1": f"{r[2]}:{r[3]}" if r[3] else r[2], "IP2:PORT2": f"{r[5]}:{r[6]}" if r[6] else r[5], "FLAGS": r[8] or ""} for r in cursor.fetchall()]
    _print_table_from_dicts(_filter_columns(["PROTO", "IFACE1", "IFACE2", "BYTES", "IP1:PORT1", "IP2:PORT2", "FLAGS"], row_dicts), row_dicts)

def print_ip_counts(conn, limit=50):
    print(f"\n--- IP Address Counts (Top {limit}) ---")
    cursor = conn.cursor()
    cursor.execute('''SELECT ip_addr, COUNT(*) as count FROM (SELECT ip_addr1 as ip_addr FROM connections WHERE ip_addr1 IS NOT NULL UNION ALL SELECT ip_addr2 FROM connections WHERE ip_addr2 IS NOT NULL) GROUP BY ip_addr ORDER BY count DESC LIMIT ?''', (limit,))
    row_dicts = [{"IP ADDRESS": r[0], "COUNT": r[1]} for r in cursor.fetchall()]
    _print_table_from_dicts(["IP ADDRESS", "COUNT"], row_dicts)

def print_port_counts(conn, limit=50):
    print(f"\n--- Port Counts (Top {limit}) ---")
    cursor = conn.cursor()
    cursor.execute('''SELECT port, COUNT(*) as count FROM (SELECT port1 as port FROM connections UNION ALL SELECT port2 FROM connections) WHERE port IS NOT NULL AND port != 0 GROUP BY port ORDER BY count DESC LIMIT ?''', (limit,))
    row_dicts = [{"PORT": r[0], "COUNT": r[1]} for r in cursor.fetchall()]
    _print_table_from_dicts(["PORT", "COUNT"], row_dicts)


# --- CISCO CIRCUIT LLM INTEGRATION ---



def query_llm_for_sql(user_query: str, api_key: str) -> Optional[str]:
    """Ask OpenAI to generate a SQLite query for the connections table."""

    endpoint = "https://api.openai.com/v1/chat/completions"

    system_instruction = (
        "You are an expert SQLite SQL query generator. Convert the user's natural "
        "language request into one executable, read-only SQLite SELECT query for the "
        "'connections' table. Return only raw SQL: no explanation, markdown, or comments. "
        "Use aggregation (COUNT, SUM) and ORDER BY/LIMIT when the user asks for top items. "
        "Use only the following schema:\n\n"
        "CREATE TABLE connections (\n"
        "    id INTEGER PRIMARY KEY, protocol TEXT, interface1 TEXT, ip_addr1 TEXT, port1 INTEGER,\n"
        "    xlated_ip1 TEXT, xlated_port1 INTEGER,\n"
        "    interface2 TEXT, ip_addr2 TEXT, port2 INTEGER,\n"
        "    xlated_ip2 TEXT, xlated_port2 INTEGER,\n"
        "    idle_time TEXT, uptime TEXT, bytes_transferred INTEGER,\n"
        "    flags TEXT, initiator_ip TEXT, responder_ip TEXT,\n"
        "    forward_current_rate INTEGER, reverse_current_rate INTEGER,\n"
        "    forward_max_rate INTEGER, reverse_max_rate INTEGER,\n"
        "    forward_time_last_max TEXT, reverse_time_last_max TEXT\n"
        ")"
    )

    payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": user_query},
        ],
        "temperature": 0,
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    for attempt in range(3):
        try:
            print("[*] Generating SQL via OpenAI...")
            response = requests.post(
                endpoint, headers=headers, json=payload, timeout=60
            )
            response.raise_for_status()

            sql_query = response.json()["choices"][0]["message"]["content"].strip()

            # Handle an occasional markdown-wrapped response.
            if sql_query.startswith("```"):
                sql_query = re.sub(r"^```(?:sql)?\s*", "", sql_query, flags=re.I)
                sql_query = re.sub(r"\s*```$", "", sql_query)

            return sql_query.strip()

        except requests.exceptions.HTTPError as e:
            print(f"[!] OpenAI HTTP error: {e}")
            if response.status_code in (401, 403):
                print("[!] Check that OPENAI_API_KEY is valid and has API access.")
                return None
            if response.status_code not in (429, 500, 502, 503, 504):
                return None
        except (requests.exceptions.RequestException, KeyError, IndexError, ValueError) as e:
            print(f"[!] OpenAI request or response error: {e}")

        if attempt < 2:
            time.sleep(2)

    return None


def execute_llm_sql(conn: sqlite3.Connection, sql_query: str):
    try:
        cursor = conn.cursor()
        cursor.execute(sql_query)
        results = cursor.fetchall()
        if cursor.description is None:
            print("\n[!] Query executed successfully, but no columns were returned.")
            return

        col_names = [d[0] for d in cursor.description]
        row_dicts = [{col_names[i]: row[i] for i in range(len(col_names))} for row in results]
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

def main():
    # --- Load Environment Variables ---
    try:
        from dotenv import load_dotenv
        load_dotenv(override=True)
    except ImportError:
        pass

    openai_api_key = os.environ.get("OPENAI_API_KEY")

    input_file_path = None
    if len(sys.argv) > 1:
        input_file_path = sys.argv[1]
    else:
        while True:
            user_input = input("Please enter the path to the ASA connection log file (or press Enter to exit): ").strip()
            if user_input:
                input_file_path = user_input
                break
            else:
                sys.exit(0)

    conn = init_db()
    detected_format = process_file(conn, input_file_path)

    if detected_format is None:
        conn.close()
        sys.exit(1)

    print("\n\n========================================================")
    print("      INITIAL LOG ANALYSIS REPORTS        ")
    print("========================================================")
    print_top_bytes_entries(conn)
    print_top_idle_time_entries(conn)
    print_same_interface_entries(conn) 
    print_top_flag_n_entries(conn)
    print_ip_counts(conn, 50)
    print_port_counts(conn, 50)

    print("\n========================================================")
    print("      NATURAL LANGUAGE DATABASE QUERY INTERFACE        ")
    print("========================================================")

    if not openai_api_key:
        print("[!] LLM interface disabled because OPENAI_API_KEY is missing.")
    else:
        # Protect the imported database even if the model generates a
        # non-read-only statement.
        conn.execute("PRAGMA query_only = ON")

        print("[*] LLM interface is active (via OpenAI).")
        print("Try queries like: 'show me the top 10 protocols by count',")
        print("or 'list all connections where the initiator is 192.168.2.20'.")
        print("Type 'exit' or 'quit' to end the session.")

        while True:
            try:
                user_input = input("\nQuery > ").strip()
                if user_input.lower() in ("exit", "quit"):
                    break
                if not user_input:
                    continue

                sql_query = query_llm_for_sql(user_input, openai_api_key)

                if sql_query:
                    execute_llm_sql(conn, sql_query)

            except Exception as e:
                print(f"\n[!] An unhandled error occurred in the loop: {e}")
                break

if __name__ == "__main__":
    main()
