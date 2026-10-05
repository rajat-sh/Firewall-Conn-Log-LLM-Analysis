import sqlite3
import os
import sys
import re
import time
import httpx
from typing import List, Tuple, Optional, Dict, Any
import warnings

# Hide LangChain Deprecation Warnings from the console
warnings.filterwarnings("ignore", category=DeprecationWarning) # <-- Add this


# --- DEPENDENCY IMPORTS ---
try:
    from langchain_community.utilities.sql_database import SQLDatabase
    from langchain_openai import ChatOpenAI
    from langchain_community.agent_toolkits import create_sql_agent
except ImportError:
    print("[!] LangChain is not installed. Please install it (pip install langchain langchain-openai langchain-community).")
    sys.exit(1)


# --- CONFIGURATION ---
DB_NAME = 'asa_connections.db'
BATCH_SIZE = 5000

# Standard OpenAI model
LLM_MODEL = 'gpt-4o' 

CUSTOM_ASA_PREFIX = """You are an expert Cisco ASA Firewall Network Analyst and an AI agent designed to interact with a SQLite database containing firewall connection logs.

Rules:
- Given an input question, create a syntactically correct SQLite query to run, then look at the results and return the answer.
- Unless the user specifies a specific number of examples, ALWAYS limit your query to at most 50 results using the LIMIT clause.
- Order the results by a relevant column (like bytes_transferred or idle_time) to return the most interesting examples.
- Never query for all the columns from a specific table, only ask for the relevant columns.
- DO NOT make any DML statements (INSERT, UPDATE, DELETE, DROP etc.) to the database. You are READ-ONLY.
- DO NOT MAKE UP AN ANSWER. ONLY USE THE RESULTS EXTRACTED FROM THE DATABASE.
- ALWAYS, as part of your final answer, include a section that starts with "Explanation:" detailing how you found the answer.
- ALWAYS include the raw SQL query you used inside a markdown code block at the very end of your response.
"""

# --- UTILS FOR PRINTING WITH DYNAMIC COLUMNS ---

def _is_blank(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, (int, float)):
        value = str(value) 
    s = str(value).strip()
    return s == "" or s.upper() == "NULL" or s == "-" or s == "0" 


def _filter_columns(headers: List[str], rows: List[Dict[str, Any]]) -> List[str]:
    if not rows:
        return headers
    kept = []
    for h in headers:
        any_non_blank = any(not _is_blank(r.get(h)) for r in rows)
        if any_non_blank:
            kept.append(h)
    return kept


def _print_table_from_dicts(headers: List[str], rows: List[Dict[str, Any]]):
    if not headers:
        print("[!] Nothing to display (all columns were blank).")
        return

    col_widths = {h: len(h) for h in headers}
    for r in rows:
        for h in headers:
            v = r.get(h)
            s = "" if v is None else str(v)
            if len(s) > col_widths[h]:
                col_widths[h] = len(s)

    for h in headers:
        col_widths[h] += 2

    header_line = "".join(h.ljust(col_widths[h]) for h in headers)
    print(header_line)
    print("-" * len(header_line))

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
    print("\n--- DATABASE SCHEMA INITIALIZED ---")
    return conn

def _time_to_seconds(time_str: str) -> int:
    if not time_str:
        return 0
    time_str = re.sub(r'\s+', '', time_str).strip()
    if ':' in time_str:
        parts = [int(p) for p in time_str.split(':')]
        if len(parts) == 3: return parts[0] * 3600 + parts[1] * 60 + parts[2]
        elif len(parts) == 2: return parts[0] * 60 + parts[1]
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
        r'^(UDP|TCP|ICMP|IP)\s+([^:\s]+):\s*([^/\s]+/[\d\.]+)\s*$([^/\s]+/[\d\.]+)$\s*'
        r'([^:\s]+):\s*([^/\s]+/[\d\.]+)\s*$([^/\s]+/[\d\.]+)$'
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
        return None

def _parse_format5_record(record_lines: List[str]) -> Optional[Tuple[Any, ...]]:
    if not record_lines: return None
    full_record_text = ' '.join(line.strip() for line in record_lines)
    try:
        main_regex = re.compile(
            r'^(UDP|TCP|ICMP|IP)\s+([^:\s]+):\s*([^/\s]+/[\d\.]+)\s*$([^/\s]+/[\d\.]+)$\s*'
            r'([^:\s]+):\s*([^/\s]+/[\d\.]+)\s*$([^/\s]+/[\d\.]+)$'
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
        xlate_pattern_re = re.compile(r'^(UDP|TCP|ICMP|IP)\s+\S+:\s*[^(\s]+/\d+\s+$[^)]+$')
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


# --- MAIN EXECUTION ---

def main():
    # 1. Load Environment Variables gracefully
    try:
        from dotenv import load_dotenv
        load_dotenv(override=True)
    except ImportError:
        pass 

    conn = None 
    
    try:
        # 2. Capture API Key (Now Optional!)
        llm_enabled = True
        api_key = os.environ.get('OPENAI_API_KEY')
        if not api_key:
            print("\n" + "="*60)
            api_key = input("Please enter your OpenAI API key (sk-...)\n[Press ENTER to skip and use Static Analysis only]: ").strip()
            if not api_key:
                print("\n[*] No API key provided. Natural language chatting will be disabled.")
                llm_enabled = False

        # 3. Configure HTTP Client (Ignores SSL verification for enterprise firewalls)
        http_client = httpx.Client(verify=False)

        # 4. Get the local file path
        input_file_path = None
        if len(sys.argv) > 1:
            input_file_path = sys.argv[1]
        else:
            while True:
                user_input = input("\nPlease enter the local path to the ASA connection log file (or press Enter to exit): ").strip()
                user_input = user_input.strip("'\"") 
                if user_input:
                    input_file_path = user_input
                    break
                else:
                    sys.exit(0)

        if not os.path.isfile(input_file_path):
            print(f"[!] Error: File '{input_file_path}' not found.")
            sys.exit(1)

        # 5. Initialize Database and Process the Log
        conn = init_db()
        detected_format = process_file(conn, input_file_path)

        if detected_format is None:
            sys.exit(1)

        # Print static reports (These happen regardless of API key!)
        print("\n\n========================================================")
        print("      INITIAL LOG ANALYSIS REPORTS (STATIC)       ")
        print("========================================================")
        print_top_bytes_entries(conn)
        print_top_idle_time_entries(conn)
        print_same_interface_entries(conn) 
        print_top_flag_n_entries(conn)
        print_ip_counts(conn, 50)
        print_port_counts(conn, 50)

        # 6. Check if we should initialize the LLM
        if llm_enabled:
            print("\n========================================================")
            print("      LANGCHAIN SQL AGENT INTERFACE        ")
            print("========================================================")
            print("[*] Initializing LangChain AI Agent...")
            
            sql_db = SQLDatabase.from_uri(f"sqlite:///{DB_NAME}")
            
            llm = ChatOpenAI(
                model=LLM_MODEL, 
                api_key=api_key, 
                temperature=0.0,
                http_client=http_client
            )
            
            agent_executor = create_sql_agent(
                llm=llm,
                db=sql_db,
                agent_type="openai-tools",
                prefix=CUSTOM_ASA_PREFIX,
                verbose=False 
            )

            print("[*] LLM interface is active.")
            print("Try queries like: 'show me the top 10 protocols by count'")
            print("Type 'exit' or 'quit' to end the session.\n")

            # Interactive Chat Loop
            while True:
                try:
                    user_input = input("Query > ").strip()
                    if user_input.lower() in ['exit', 'quit']:
                        print("\nShutting down gracefully...")
                        break
                    if not user_input:
                        continue

                    print("Thinking...")
                    
                    response = agent_executor.invoke({"input": user_input})
                    
                    print("\nAnswer:")
                    print(response["output"])
                    print("-" * 60 + "\n")

                except KeyboardInterrupt:
                    print("\n[!] User interrupted session (Ctrl+C). Shutting down...")
                    break
                except Exception as e:
                    print(f"\n[!] An unhandled error occurred in the query loop: {e}\n")
        else:
            print("\n========================================================")
            print("[*] Static Analysis Complete.")
            print("[*] Exiting program because no OpenAI API key was provided.")
            print("========================================================\n")

    except Exception as e:
         print(f"\n[!] A fatal error occurred: {e}")

    finally:
        # 7. Safe Cleanup (Guaranteed to execute)
        if conn:
            conn.close()
        if os.path.exists(DB_NAME):
            os.remove(DB_NAME)
            print(f"[*] Cleanup complete: Temporary database '{DB_NAME}' deleted.")

if __name__ == "__main__":
    main()
