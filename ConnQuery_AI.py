import sqlite3
import os
import sys
import re
import json
import time
from typing import List, Tuple, Optional, Dict, Any

# --- DEPENDENCY IMPORTS ---
# This script assumes 'requests' is installed for API communication.
# You must install it (e.g., pip install requests).
try:
    import requests
except ImportError:
    print("[!] The 'requests' library is not installed. Please install it (pip install requests).")
    sys.exit(1)


# --- CONFIGURATION ---
DB_NAME = 'asa_connections.db'
# INPUT_FILENAME = 'asa_conn_log.txt' # Removed: This will now be determined dynamically
BATCH_SIZE = 5000
LLM_MODEL = 'gemini-2.5-flash-preview-09-2025'
LLM_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{LLM_MODEL}:generateContent"


# --- API KEY MANAGEMENT ---
# IMPORTANT: This script reads the key from the key from environment variable.
# You must set the GEMINI_API_KEY environment variable (e.g., by sourcing the .env file).
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


# --- DATABASE UTILITIES & LOGIC ---

def init_db() -> sqlite3.Connection:
    """
    Initializes the SQLite database with a comprehensive schema.
    Returns the connection object.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('DROP TABLE IF EXISTS connections')

    # This is the SCHEMA provided to the LLM for SQL generation
    cursor.execute('''
        CREATE TABLE connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol TEXT,
            interface1 TEXT,
            ip_addr1 TEXT,        -- Original/Real IP 1
            port1 INTEGER,        -- Original/Real Port 1
            xlated_ip1 TEXT,      -- Translated IP 1 (Used in F3)
            xlated_port1 INTEGER, -- Translated Port 1 (Used in F3)
            interface2 TEXT,
            ip_addr2 TEXT,        -- Original/Real IP 2
            port2 INTEGER,        -- Original/Real Port 2
            xlated_ip2 TEXT,      -- Translated IP 2 (Used in F3)
            xlated_port2 INTEGER, -- Translated Port 2 (Used in F3)
            idle_time TEXT,
            uptime TEXT,          -- Uptime of the connection
            bytes_transferred INTEGER,
            flags TEXT,
            initiator_ip TEXT,    -- Used in F2
            responder_ip TEXT     -- Used in F2
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
    """
    Converts time string (H:MM:SS or Xs/XmXs) to total seconds for numerical sorting.
    """
    if not time_str:
        return 0

    # Format 1: H:MM:SS or M:SS (Contains colons)
    if ':' in time_str:
        parts = [int(p) for p in time_str.split(':')]
        if len(parts) == 3:  # H:MM:SS
            return parts[0] * 3600 + parts[1] * 60 + parts[2]
        elif len(parts) == 2: # M:SS (e.g., 0:57)
            return parts[0] * 60 + parts[1]
        return 0

    # Format 2/3: Xs (seconds) or XmXs (minutes and seconds)
    total_seconds = 0

    # Matches Xm (e.g., '2m')
    m_match = re.search(r'(\d+)m', time_str)
    if m_match:
        total_seconds += int(m_match.group(1)) * 60

    # Matches Xs (e.g., '2s')
    s_match = re.search(r'(\d+)s', time_str)
    if s_match:
        total_seconds += int(s_match.group(1))

    return total_seconds

def _parse_ip_port_slash(ip_port_str: str) -> Tuple[str, int]:
    """Helper function to split IP and Port using '/'."""
    try:
        ip, port_str = ip_port_str.rsplit('/', 1)
        # Clean the port string (removes trailing comma/whitespace)
        clean_port_str = port_str.replace(',', '').strip()
        return ip, int(clean_port_str)
    except ValueError:
        # If rsplit fails or int conversion fails, assume it's an IP or protocol name, and port is 0
        return ip_port_str.replace(',', '').strip(), 0

def _parse_format1_line(line: str) -> Optional[Tuple[Any, ...]]:
    """
    Parses a single line in Format 1 (colon-separated IP:Port, H:MM:SS idle).
    Returns a 17-element tuple. Uptime, xlated, init/resp IPs are None.
    """
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
            None, None, # xlated_ip1, xlated_port1
            int2, ip_addr2, port2,
            None, None, # xlated_ip2, xlated_port2
            idle_time,
            None, # uptime
            int(bytes_val_str), flags,
            None, # initiator_ip
            None  # responder_ip
        )
        return data
    except Exception as e:
        print(f"[!] Format 1 Parsing Error on line: {line.strip()}. Error: {e}")
        return None

def _parse_format2_record(full_record: str) -> Optional[Tuple[Any, ...]]:
    """
    Parses a single or multi-line record in Format 2.
    Returns a 17-element tuple. Xlated IPs are None.
    """
    # 1. Main Connection Info Regex - Made more specific to avoid matching header lines
    main_match = re.search(
        r'^(UDP|TCP|ICMP|IP)\s+([^:\s]+):\s*([^/\s]+/[\d\.]+[^:\s]*)\s+([^:\s]+):\s*([^/\s]+/[\d\.]+[^:\s]*)',
        full_record # Added ^ to anchor to start, and specific protocols
    )

    if not main_match:
         # Fallback for non-port protocols like ICMP that might not have /port, but still need protocol and interfaces
        main_match = re.search(
            r'^(UDP|TCP|ICMP|IP)\s+([^:\s]+):\s*([^:\s,]+)\s+([^:\s]+):\s*([^:\s,]+)',
            full_record
        )
        if not main_match:
             # print(f"[!] Format 2 Main Info Error: Could not extract main connection info from: {full_record.strip()}")
             return None


    protocol = main_match.group(1)
    int1 = main_match.group(2).replace(':', '')
    ip1_raw = main_match.group(3)
    int2 = main_match.group(4).replace(':', '')
    ip2_raw = main_match.group(5)

    ip_addr1, port1 = _parse_ip_port_slash(ip1_raw)
    ip_addr2, port2 = _parse_ip_port_slash(ip2_raw)

    # 2. Metrics Regex (flags, idle, uptime, bytes)
    flags_match = re.search(r'flags\s+([^\s,]+)', full_record)
    flags = flags_match.group(1).strip() if flags_match else ""

    idle_match = re.search(r'idle\s+([^\s,]+)', full_record)
    idle_time = idle_match.group(1).strip() if idle_match else ""

    # Extract Uptime
    uptime_match = re.search(r'uptime\s+([^\s,]+)', full_record)
    uptime = uptime_match.group(1).strip() if uptime_match else None # Default to None if not found, consistent with F1

    bytes_match = re.search(r'bytes\s+(\d+)', full_record)
    bytes_val = int(bytes_match.group(1)) if bytes_match else 0

    # 3. Initiator/Responder (Optional)
    init_resp_match = re.search(
        r'Initiator:\s*([^,\s]+),\s*Responder:\s*([^,\s]+)',
        full_record
    )
    initiator_ip = init_resp_match.group(1) if init_resp_match else None
    responder_ip = init_resp_match.group(2) if init_resp_match else None

    return (
        protocol, int1, ip_addr1, port1,
        None, None, # xlated_ip1, xlated_port1
        int2, ip_addr2, port2,
        None, None, # xlated_ip2, xlated_port2
        idle_time, uptime, # Uptime field included
        bytes_val, flags, initiator_ip, responder_ip
    )

def _parse_format3_line(full_record: str) -> Optional[Tuple[Any, ...]]:
    """
    Parses a single or multi-line record in Format 3 (IP/Port (XlatedIP/XlatedPort)).
    This version is more robust to variations in metric order and includes initiator/responder.
    Returns a 17-element tuple.
    """
    # Main connection info regex (Side 1 & Side 2) - Anchored to start
    main_regex = re.compile(
        r'^(UDP|TCP|ICMP|IP)\s+([^:\s]+):\s*([^/\s]+/[\d\.]+)\s*\(([^/\s]+/[\d\.]+)\)\s*' # Side 1 (Real & Xlated)
        r'([^:\s]+):\s*([^/\s]+/[\d\.]+)\s*\(([^/\s]+/[\d\.]+)\)'          # Side 2 (Real & Xlated)
    )

    main_match = main_regex.search(full_record)

    if not main_match:
        # print(f"[!] Format 3 Main Info Error: Could not match main connection components in: {full_record.strip()}")
        return None

    try:
        protocol, int1, ip1_raw, xip1_raw, int2, ip2_raw, xip2_raw = main_match.groups()

        # Parse Real IPs/Ports
        ip_addr1, port1 = _parse_ip_port_slash(ip1_raw)
        ip_addr2, port2 = _parse_ip_port_slash(ip2_raw)

        # Parse Translated IPs/Ports
        xlated_ip1, xlated_port1 = _parse_ip_port_slash(xip1_raw)
        xlated_ip2, xlated_port2 = _parse_ip_port_slash(xip2_raw)

        # Extract metrics and initiator/responder separately from the full record string
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

def process_file(conn: sqlite3.Connection, filename: str): # Modified: Added filename argument
    """
    Reads the file, automatically detects log format from the first line,
    parses data using the appropriate function, and bulk inserts into the
    single database table.
    """
    cursor = conn.cursor()

    cursor.execute('DELETE FROM connections')
    conn.commit()
    print("[*] Database connections table cleared before processing.")

    data_batch = []
    total_processed = 0
    format_type = None

    try:
        with open(filename, 'r') as f: # Modified: Use filename argument
            lines = f.readlines()

        # --- 1. Format Detection ---
        # Find the first line that looks like a connection record
        start_processing_index = 0
        for idx, line in enumerate(lines):
            stripped_line = line.strip()
            if not stripped_line:
                continue

            # --- DEBUG: Print current line being evaluated for format detection ---
            # print(f"DEBUG: Attempting format detection for line {idx}: '{stripped_line}'")
            # --------------------------------------------------------------------

            # Prioritize most specific formats first
            # Format 3 Check: Has translated IP/Port in parentheses and starts with protocol
            if re.search(r'^(UDP|TCP|ICMP|IP)\s+\w+:\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+\s+\(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+\)', stripped_line):
                format_type = 3
                start_processing_index = idx
                # print(f"DEBUG: Line {idx} identified as Format 3.")
                break
            # Format 1 Check: Second most specific - colon-separated IP:Port and 'idle'
            # Ensure it doesn't accidentally catch a Format 3 line that also has 'idle'.
            elif re.search(r'^(UDP|TCP|ICMP|IP)\s+\w+\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\s+\w+\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+,\s*idle\s+([^\s,]+)', stripped_line):
                format_type = 1
                start_processing_index = idx
                # print(f"DEBUG: Line {idx} identified as Format 1.")
                break
            # Format 2 Check: Has IP/Port using slash notation and starts with protocol, but no translated IP/Port in parentheses
            elif re.search(r'^(UDP|TCP|ICMP|IP)\s+\w+:\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+', stripped_line):
                format_type = 2
                start_processing_index = idx
                # print(f"DEBUG: Line {idx} identified as Format 2.")
                break

        if format_type is None:
            print("[!] Error: Could not determine log format from the file content after scanning all lines. No valid connection record found.")
            return

        print(f"[*] Detected format: Format {format_type}")

        # Start processing from the detected index
        i = start_processing_index
        while i < len(lines):
            line = lines[i].strip()
            i += 1

            if not line:
                continue

            record_data = None
            full_record = line

            # --- DEBUG: Print current line being processed ---
            # print(f"\nDEBUG: Processing record starting at line {i-1} (original index) for Format {format_type}: '{line.strip()}'")
            # -------------------------------------------------

            if format_type == 3:
                # Format 3 can span multiple lines if it includes Initiator/Responder info
                # Check for the optional Initiator/Responder line (indented)
                if i < len(lines) and lines[i].strip().startswith('Initiator:'):
                    full_record += " " + lines[i].strip()
                    i += 1 # Consume the Initiator line
                record_data = _parse_format3_line(full_record)

            elif format_type == 2:
                # Format 2 aggregates the metrics line and the optional Initiator line

                # 1. Check for the metrics continuation line (flags, idle, bytes)
                if i < len(lines) and lines[i].startswith((' ', '\t')) and ('flags' in lines[i] or 'bytes' in lines[i]):
                    full_record += " " + lines[i].strip()
                    i += 1 # Consume the metrics line

                # 2. Check for the optional Initiator/Responder line
                if i < len(lines) and lines[i].strip().startswith('Initiator:'):
                    full_record += " " + lines[i].strip()
                    i += 1 # Consume the Initiator line

                record_data = _parse_format2_record(full_record)

            elif format_type == 1:
                # Format 1 is a single line
                record_data = _parse_format1_line(full_record)

            # --- DEBUG: Print parsing result ---
            # if record_data:
            #     print(f"  DEBUG: Parsed record_data (first 5 elements): {record_data[:5]}...")
            # else:
            #     print(f"  DEBUG: Parsing returned None for record: '{full_record.strip()}'")
            # -----------------------------------

            # record_data must be a tuple of 17 elements
            if record_data and len(record_data) == 17:
                data_batch.append(record_data)
                total_processed += 1
            elif record_data:
                 print(f"[!] Warning: Parsed record has unexpected length {len(record_data)}. Expected 17. Skipping line: {full_record}")

            # Bulk insert when the batch is full
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

        # Insert any remaining records
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

        print(f"[*] Successfully processed {total_processed} entries from {filename} into database.") # Modified: Use filename argument

    except FileNotFoundError:
        print(f"[!] Error: File {filename} not found. Please ensure the log file exists and contains data.") # Modified: Use filename argument
        sys.exit(1) # Exit if file not found
    except Exception as e:
        print(f"[!] An unexpected error occurred during file processing: {e}")
        sys.exit(1) # Exit on unexpected error

# --- REPORTING FUNCTIONS (CORRECTED to include port numbers and interfaces) ---

def print_database(conn):
    """Queries and prints all rows from the database."""
    print("\n--- Database Entries (Detailed View) ---")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM connections")
    rows = cursor.fetchall()

    # Updated header to include ports and adjust widths
    header = (
        f"{'ID':<4} {'PROTO':<6} {'IFACE1':<10} {'IP1:PORT1':<22} {'X-IP1:X-PORT1':<22} {'IFACE2':<10} {'IP2:PORT2':<22} {'X-IP2:X-PORT2':<22} "
        f"{'BYTES':<8} {'IDLE':<10} {'UPTIME':<10} {'FLAGS':<6} {'INIT_IP':<16} {'RESP_IP':<16}"
    )
    print(header)
    print("-" * len(header))

    for row in rows:
        # Correct unpacking for all 18 columns
        r_id, proto, int1, ip1, port1, xip1, xport1, int2, ip2, port2, xip2, xport2, idle, uptime_val, bytes_t, flags, init_ip, resp_ip = row

        # Format IP:Port strings, handling None/0 for xlated and port
        ip1_port_display = f"{ip1}:{port1}" if port1 is not None and port1 != 0 else (ip1 if ip1 else "-")
        ip2_port_display = f"{ip2}:{port2}" if port2 is not None and port2 != 0 else (ip2 if ip2 else "-")

        # Display '-' if xlated IP/Port is None, otherwise format as IP:Port
        xip1_port_display = f"{xip1}:{xport1}" if xip1 is not None and xport1 is not None and xport1 != 0 else (xip1 if xip1 else "-")
        xip2_port_display = f"{xip2}:{xport2}" if xip2 is not None and xport2 is not None and xport2 != 0 else (xip2 if xip2 else "-")

        init_ip_display = init_ip if init_ip else "-"
        resp_ip_display = resp_ip if resp_ip else "-"

        print(
            f"{r_id:<4} {proto:<6} {int1:<10} {ip1_port_display:<22} {xip1_port_display:<22} {int2:<10} {ip2_port_display:<22} {xip2_port_display:<22} "
            f"{bytes_t:<8} {idle:<10} {uptime_val if uptime_val else '-':<10} {flags:<6} {init_ip_display:<16} {resp_ip_display:<16}"
        )
    print("-" * len(header))
    print("\n")

def print_top_bytes_entries(conn, limit=50):
    """Queries and prints the top 50 connection entries sorted by bytes_transferred in descending order."""
    print(f"\n--- Top {limit} Connections by Bytes Transferred (Descending) ---")
    cursor = conn.cursor()

    # Corrected SELECT statement to include interface and port columns
    cursor.execute(f'''
        SELECT
            id, protocol, interface1, ip_addr1, port1, xlated_ip1, xlated_port1,
            interface2, ip_addr2, port2, xlated_ip2, xlated_port2,
            bytes_transferred, idle_time, uptime, flags, initiator_ip, responder_ip
        FROM
            connections
        ORDER BY
            bytes_transferred DESC, id DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()

    # Updated header to include ports and adjust widths
    header = (
        f"{'ID':<4} {'PROTO':<6} {'BYTES':<8} {'IFACE1':<10} {'IP1:PORT1':<22} {'X-IP1:X-PORT1':<22} {'IFACE2':<10} {'IP2:PORT2':<22} {'X-IP2:X-PORT2':<22} "
        f"{'IDLE':<10} {'UPTIME':<10} {'FLAGS'}"
    )
    print(header)
    print("-" * len(header))

    if not rows:
        print("No entries found in the database.")
        return

    for row in rows:
        # Correct unpacking for the selected columns
        r_id, proto, int1, ip1, port1, xip1, xport1, int2, ip2, port2, xip2, xport2, bytes_t, idle, uptime_val, flags, init_ip, resp_ip = row

        ip1_port_display = f"{ip1}:{port1}" if port1 is not None and port1 != 0 else (ip1 if ip1 else "-")
        ip2_port_display = f"{ip2}:{port2}" if port2 is not None and port2 != 0 else (ip2 if ip2 else "-")
        xip1_port_display = f"{xip1}:{xport1}" if xip1 is not None and xport1 is not None and xport1 != 0 else (xip1 if xip1 else "-")
        xip2_port_display = f"{xip2}:{xport2}" if xip2 is not None and xport2 is not None and xport2 != 0 else (xip2 if xip2 else "-")

        print(
            f"{r_id:<4} {proto:<6} {bytes_t:<8} {int1:<10} {ip1_port_display:<22} {xip1_port_display:<22} {int2:<10} {ip2_port_display:<22} {xip2_port_display:<22} "
            f"{idle:<10} {uptime_val if uptime_val else '-':<10} {flags}"
        )
    print("-" * len(header))
    print("\n")

def print_top_idle_time_entries(conn, limit=50):
    """
    Queries all connection entries and sorts them in Python using a utility
    function to correctly handle time formats.
    """
    print(f"\n--- Top {limit} Connections by Idle Time (Descending) ---")
    cursor = conn.cursor()

    # Corrected SELECT statement to include interface and port columns
    cursor.execute('''
        SELECT
            id, protocol, interface1, ip_addr1, port1, xlated_ip1, xlated_port1,
            interface2, ip_addr2, port2, xlated_ip2, xlated_port2,
            idle_time, uptime, bytes_transferred, flags
        FROM
            connections
    ''')
    rows = cursor.fetchall()

    # Sort key is idle_time (index 12 in the new row structure)
    sorted_rows = sorted(
        rows,
        key=lambda r: _time_to_seconds(r[12] or "0s"), # idle_time is now at index 12
        reverse=True
    )

    rows_to_display = sorted_rows[:limit]

    # Updated header to include ports and adjust widths
    header = (
        f"{'ID':<4} {'PROTO':<6} {'IDLE':<10} {'UPTIME':<10} {'IFACE1':<10} {'IP1:PORT1':<22} {'X-IP1:X-PORT1':<22} {'IFACE2':<10} {'IP2:PORT2':<22} {'X-IP2:X-PORT2':<22} "
        f"{'BYTES':<8} {'FLAGS'}"
    )
    print(header)
    print("-" * len(header))

    if not rows_to_display:
        print("No entries found in the database.")
        return

    for row in rows_to_display:
        # Correct unpacking for the selected columns
        r_id, proto, int1, ip1, port1, xip1, xport1, int2, ip2, port2, xip2, xport2, idle, uptime_val, bytes_t, flags = row

        ip1_port_display = f"{ip1}:{port1}" if port1 is not None and port1 != 0 else (ip1 if ip1 else "-")
        ip2_port_display = f"{ip2}:{port2}" if port2 is not None and port2 != 0 else (ip2 if ip2 else "-")
        xip1_port_display = f"{xip1}:{xport1}" if xip1 is not None and xport1 is not None and xport1 != 0 else (xip1 if xip1 else "-")
        xip2_port_display = f"{xip2}:{xport2}" if xip2 is not None and xport2 is not None and xport2 != 0 else (xip2 if xip2 else "-")

        print(
            f"{r_id:<4} {proto:<6} {idle:<10} {uptime_val if uptime_val else '-':<10} {int1:<10} {ip1_port_display:<22} {xip1_port_display:<22} {int2:<10} {ip2_port_display:<22} {xip2_port_display:<22} "
            f"{bytes_t:<8} {flags}"
        )
    print("-" * len(header))
    print("\n")


def print_top_uptime_entries(conn, limit=50):
    """
    Queries all connection entries and sorts them in Python using a utility
    function to correctly handle time formats, focusing on Uptime.
    """
    print(f"\n--- Top {limit} Connections by Uptime (Descending) ---")
    cursor = conn.cursor()

    # Corrected SELECT statement to include interface and port columns
    cursor.execute('''
        SELECT
            id, protocol, interface1, ip_addr1, port1, xlated_ip1, xlated_port1,
            interface2, ip_addr2, port2, xlated_ip2, xlated_port2,
            idle_time, uptime, bytes_transferred, flags
        FROM
            connections
    ''')
    rows = cursor.fetchall()

    # Sort key is uptime (index 13 in the new row structure)
    sorted_rows = sorted(
        rows,
        key=lambda r: _time_to_seconds(r[13] or "0s"), # Uptime is now at index 13
        reverse=True
    )

    rows_to_display = sorted_rows[:limit]

    # Updated header to include ports and adjust widths
    header = (
        f"{'ID':<4} {'PROTO':<6} {'UPTIME':<10} {'IDLE':<10} {'IFACE1':<10} {'IP1:PORT1':<22} {'X-IP1:X-PORT1':<22} {'IFACE2':<10} {'IP2:PORT2':<22} {'X-IP2:X-PORT2':<22} "
        f"{'BYTES':<8} {'FLAGS'}"
    )
    print(header)
    print("-" * len(header))

    if not rows_to_display:
        print("No entries found in the database.")
        return

    for row in rows_to_display:
        # Correct unpacking for the selected columns
        r_id, proto, int1, ip1, port1, xip1, xport1, int2, ip2, port2, xip2, xport2, idle, uptime_val, bytes_t, flags = row

        ip1_port_display = f"{ip1}:{port1}" if port1 is not None and port1 != 0 else (ip1 if ip1 else "-")
        ip2_port_display = f"{ip2}:{port2}" if port2 is not None and port2 != 0 else (ip2 if ip2 else "-")
        xip1_port_display = f"{xip1}:{xport1}" if xip1 is not None and xport1 is not None and xport1 != 0 else (xip1 if xip1 else "-")
        xip2_port_display = f"{xip2}:{xport2}" if xip2 is not None and xport2 is not None and xport2 != 0 else (xip2 if xip2 else "-")

        print(
            f"{r_id:<4} {proto:<6} {uptime_val if uptime_val else '-':<10} {idle:<10} {int1:<10} {ip1_port_display:<22} {xip1_port_display:<22} {int2:<10} {ip2_port_display:<22} {xip2_port_display:<22} "
            f"{bytes_t:<8} {flags}"
        )
    print("-" * len(header))
    print("\n")


def print_same_interface_entries(conn, limit=50):
    """Queries and prints the top 50 connection entries where interface1 equals interface2,
    sorted by bytes_transferred in descending order."""
    print(f"\n--- Top {limit} Same-Interface Connections by Bytes Transferred (Descending) ---")
    cursor = conn.cursor()

    # Corrected SELECT statement to include port columns
    cursor.execute(f'''
        SELECT
            id, protocol, interface1, ip_addr1, port1, xlated_ip1, xlated_port1,
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

    # Updated header to include ports and adjust widths
    header = (
        f"{'ID':<4} {'PROTO':<6} {'IFACE':<10} {'BYTES':<8} {'IP1:PORT1':<22} {'X-IP1:X-PORT1':<22} {'IP2:PORT2':<22} {'X-IP2:X-PORT2':<22} "
        f"{'IDLE':<10} {'UPTIME':<10} {'FLAGS'}"
    )
    print(header)
    print("-" * len(header))

    if not rows:
        print("No connections found where interface1 and interface2 are the same.")
        return

    for row in rows:
        # Correct unpacking for the selected columns
        r_id, proto, interface, ip1, port1, xip1, xport1, ip2, port2, xip2, xport2, bytes_t, idle, uptime_val, flags = row

        ip1_port_display = f"{ip1}:{port1}" if port1 is not None and port1 != 0 else (ip1 if ip1 else "-")
        ip2_port_display = f"{ip2}:{port2}" if port2 is not None and port2 != 0 else (ip2 if ip2 else "-")
        xip1_port_display = f"{xip1}:{xport1}" if xip1 is not None and xport1 is not None and xport1 != 0 else (xip1 if xip1 else "-")
        xip2_port_display = f"{xip2}:{xport2}" if xip2 is not None and xport2 is not None and xport2 != 0 else (xip2 if xip2 else "-")

        print(
            f"{r_id:<4} {proto:<6} {interface:<10} {bytes_t:<8} {ip1_port_display:<22} {xip1_port_display:<22} {ip2_port_display:<22} {xip2_port_display:<22} "
            f"{idle:<10} {uptime_val if uptime_val else '-':<10} {flags}"
        )
    print("-" * len(header))
    print("\n")

def print_top_flag_n_entries(conn, limit=50):
    """Queries and prints the top 50 connection entries where the 'flags' column contains 'N',
    sorted by bytes_transferred in descending order. The 'N' flag often indicates NAT/X-late."""
    print(f"\n--- Top {limit} Connections with Flag 'N' by Bytes Transferred (Descending) ---")
    cursor = conn.cursor()

    # Corrected SELECT statement to include port columns
    cursor.execute(f'''
        SELECT
            id, protocol, interface1, ip_addr1, port1, xlated_ip1, xlated_port1,
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

    # Updated header to include ports and adjust widths
    header = (
        f"{'ID':<4} {'PROTO':<6} {'IFACE1':<10} {'BYTES':<8} {'IP1:PORT1':<22} {'X-IP1:X-PORT1':<22} {'IP2:PORT2':<22} {'X-IP2:X-PORT2':<22} "
        f"{'IDLE':<10} {'UPTIME':<10} {'FLAGS'}"
    )
    print(header)
    print("-" * len(header))

    if not rows:
        print("No connections found with 'N' flag.")
        return

    for row in rows:
        # Correct unpacking for the selected columns
        r_id, proto, interface1, ip1, port1, xip1, xport1, ip2, port2, xip2, xport2, bytes_t, idle, uptime_val, flags = row

        ip1_port_display = f"{ip1}:{port1}" if port1 is not None and port1 != 0 else (ip1 if ip1 else "-")
        ip2_port_display = f"{ip2}:{port2}" if port2 is not None and port2 != 0 else (ip2 if ip2 else "-")
        xip1_port_display = f"{xip1}:{xport1}" if xip1 is not None and xport1 is not None and xport1 != 0 else (xip1 if xip1 else "-")
        xip2_port_display = f"{xip2}:{xport2}" if xip2 is not None and xport2 is not None and xport2 != 0 else (xip2 if xip2 else "-")

        print(
            f"{r_id:<4} {proto:<6} {interface1:<10} {bytes_t:<8} {ip1_port_display:<22} {xip1_port_display:<22} {ip2_port_display:<22} {xip2_port_display:<22} "
            f"{idle:<10} {uptime_val if uptime_val else '-':<10} {flags}"
        )
    print("-" * len(header))
    print("\n")


def print_ip_counts(conn):
    """Queries and prints IP addresses and their occurrence counts in descending order (including xlated and init/resp IPs)."""
    print("\n--- IP Address Counts (Descending) ---")
    cursor = conn.cursor()

    # Union all IP columns (real, translated, initiator, responder)
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
    ''')
    rows = cursor.fetchall()

    header = f"{'IP ADDRESS':<35} {'COUNT'}"
    print(header)
    print("-" * len(header))

    for row in rows:
        print(f"{row[0]:<35} {row[1]}")
    print("--------------------------------------\n")

def print_port_counts(conn, limit=50):
    """Queries and prints port numbers and their occurrence counts in descending order, limited to 50."""
    print(f"\n--- Port Counts (Descending, Top {limit}) ---")
    cursor = conn.cursor()

    # Union all port columns (real and translated)
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

    header = f"{'PORT':<10} {'COUNT'}"
    print(header)
    print("-" * len(header))

    if not rows:
        print("No ports with non-zero values found.")
        return

    for row in rows:
        print(f"{row[0]:<10} {row[1]}")
    print("--------------------------------------\n")


def print_top_initiators(conn, limit=50):
    """Prints the top Initiator IP addresses grouped by count."""
    print(f"\n--- Top {limit} Initiator IPs by Connection Count ---")
    cursor = conn.cursor()

    cursor.execute(f'''
        SELECT initiator_ip, COUNT(*) as count
        FROM connections
        WHERE initiator_ip IS NOT NULL
        GROUP BY initiator_ip
        ORDER BY count DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()

    header = f"{'INITIATOR IP':<16} {'COUNT'}"
    print(header)
    print("-" * len(header))

    if not rows:
        print("No initiator IPs found.")
        return

    for ip, count in rows:
        print(f"{ip:<16} {count}")
    print("-----------------------\n")

def print_top_responders(conn, limit=50):
    """Prints the top Responder IP addresses grouped by count."""
    print(f"\n--- Top {limit} Responder IPs by Connection Count ---")
    cursor = conn.cursor()

    cursor.execute(f'''
        SELECT responder_ip, COUNT(*) as count
        FROM connections
        WHERE responder_ip IS NOT NULL
        GROUP BY responder_ip
        ORDER BY count DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()

    header = f"{'RESPONDER IP':<16} {'COUNT'}"
    print(header)
    print("-" * len(header))

    if not rows:
        print("No responder IPs found.")
        return

    for ip, count in rows:
        print(f"{ip:<16} {count}")
    print("-----------------------\n")

def print_top_initiators_with_n_flag(conn, limit=50):
    """Prints the top Initiator IPs where the connection has an 'N' flag."""
    print(f"\n--- Top {limit} Initiator IPs (Flags containing 'N') ---")
    cursor = conn.cursor()

    cursor.execute(f'''
        SELECT initiator_ip, COUNT(*) as count
        FROM connections
        WHERE initiator_ip IS NOT NULL AND (flags LIKE '%N%' OR flags LIKE '%n%')
        GROUP BY initiator_ip
        ORDER BY count DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()

    header = f"{'INITIATOR IP':<16} {'N-FLAG COUNT'}"
    print(header)
    print("-" * 28)

    if not rows:
        print("No initiator IPs found with 'N' flag.")
        return

    for ip, count in rows:
        print(f"{ip:<16} {count}")
    print("--------------------------------\n")

def print_top_responders_with_n_flag(conn, limit=50):
    """Prints the top Responder IPs where the connection has an 'N' flag."""
    print(f"\n--- Top {limit} Responder IPs (Flags containing 'N') ---")
    cursor = conn.cursor()

    cursor.execute(f'''
        SELECT responder_ip, COUNT(*) as count
        FROM connections
        WHERE responder_ip IS NOT NULL AND (flags LIKE '%N%' OR flags LIKE '%n%')
        GROUP BY responder_ip
        ORDER BY count DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()

    header = f"{'RESPONDER IP':<16} {'N-FLAG COUNT'}"
    print(header)
    print("-" * 28)

    if not rows:
        print("No responder IPs found with 'N' flag.")
        return

    for ip, count in rows:
        print(f"{ip:<16} {count}")
    print("--------------------------------\n")


# --- LLM INTEGRATION FUNCTIONS ---

def query_llm_for_sql(user_query: str) -> Optional[str]:
    """
    Sends the user's natural language query to the Gemini API to generate an SQLite SQL query.
    Implements exponential backoff for resilience.
    """
    global GEMINI_API_KEY

    if not GEMINI_API_KEY:
        print("[!] LLM API key is missing. Cannot process natural language query.")
        return None

    print(f"[*] Debug Check: API Key is loaded (Length: {len(GEMINI_API_KEY)} chars).")

    # System Instruction: Define the LLM's role and the database schema
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

    # *** FIX APPLIED HERE: Changed 'config' to 'generationConfig' ***
    payload = {
        "contents": [{"parts": [{"text": user_query}]}],
        "systemInstruction": {"parts": [{"text": system_instruction}]},
        "generationConfig": {
            "temperature": 0.0,  # Aim for deterministic output (SQL)
            "maxOutputTokens": 500
        }
    }

    headers = {'Content-Type': 'application/json'}

    max_retries = 5
    base_delay = 1

    for attempt in range(max_retries):
        try:
            print("[*] Sending query to LLM...")

            # Use the API URL and key
            response = requests.post(
                f"{LLM_API_URL}?key={GEMINI_API_KEY}",
                headers=headers,
                data=json.dumps(payload)
            )

            response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)
            result = response.json()

            # --- ADDED DEBUGGING BLOCK ---
            if 'candidates' not in result or not result['candidates']:
                print(f"[!!!] LLM did not return any candidates (Attempt {attempt + 1}/{max_retries}).")
                print(f"      Full LLM Response for debugging: {json.dumps(result, indent=2)}")
                # Check for safety feedback if no candidates
                if 'promptFeedback' in result and 'safetyRatings' in result['promptFeedback']:
                    print("      Safety Feedback:")
                    for rating in result['promptFeedback']['safetyRatings']:
                        print(f"        Category: {rating['category']}, Probability: {rating['probability']}")
                return None # Don't retry if no candidates

            # Check if 'content' or 'parts' are missing in the first candidate
            if 'content' not in result['candidates'][0] or 'parts' not in result['candidates'][0]['content']:
                print(f"[!!!] LLM candidate content structure unexpected (Attempt {attempt + 1}/{max_retries}).")
                print(f"      Full LLM Response for debugging: {json.dumps(result, indent=2)}")
                return None # Don't retry if content structure is wrong
            # --- END ADDED DEBUGGING BLOCK ---

            # Extract the raw text (which should be the SQL query)
            sql_query = result['candidates'][0]['content']['parts'][0]['text'].strip()
            return sql_query

        except requests.exceptions.HTTPError as e:
            print(f"[!] HTTP Error during LLM query (Attempt {attempt + 1}/{max_retries}): {e}")
            if response.status_code == 400:
                print(f"[!!!] BAD REQUEST (400) - Detailed error response received.")
                print(f"      Response Text for debugging (Crucial): {response.text}") # Print response body for details
                # If 400, don't retry, as the input/key won't change.
                return None
            if response.status_code == 403:
                print(f"[!!!] FORBIDDEN (403): The API key might lack permissions or the model is not available.")
        except requests.exceptions.RequestException as e:
            print(f"[!] Request Error during LLM query (Attempt {attempt + 1}/{max_retries}): {e}")
        except (KeyError, IndexError) as e:
            print(f"[!] Parsing Error: LLM response structure unexpected (Attempt {attempt + 1}/{max_retries}): {e}")
            # --- MODIFIED: Print the full result here too, as the KeyError happens before the added checks ---
            if 'result' in locals(): # Check if 'result' variable exists from the try block
                print(f"      Full LLM Response at time of KeyError: {json.dumps(result, indent=2)}")
            # --- END MODIFIED ---

        # Exponential backoff before retrying
        if attempt < max_retries - 1:
            delay = base_delay * (2 ** attempt)
            time.sleep(delay)

    print("[!] Failed to get a valid response from the LLM after multiple retries.")
    return None

def execute_llm_sql(conn: sqlite3.Connection, sql_query: str):
    """
    Executes the generated SQL query and prints the results in a formatted table.
    """
    try:
        cursor = conn.cursor()
        cursor.execute(sql_query)
        results = cursor.fetchall()
        column_names = [description[0] for description in cursor.description]

        if not column_names:
            print("\n[!] Query executed successfully, but no columns were returned.")
            return

        print("\n--- LLM QUERY RESULT ---")

        # Determine maximum width for each column dynamically
        col_widths = [len(name) for name in column_names]

        for row in results:
            for i, item in enumerate(row):
                # Ensure we are comparing strings
                col_widths[i] = max(col_widths[i], len(str(item) if item is not None else 'NULL'))

        # Padding for readability
        col_widths = [w + 2 for w in col_widths]

        # Print Header
        header_line = "".join(name.ljust(col_widths[i]) for i, name in enumerate(column_names))
        print(header_line)
        print("-" * len(header_line))

        # Print Rows
        for row in results:
            row_line = "".join(
                (str(item) if item is not None else 'NULL').ljust(col_widths[i])
                for i, item in enumerate(row)
            )
            print(row_line)

        print("-" * len(header_line))
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
    """Outputs a message about retaining files, as requested by the user."""
    print("\n[*] Cleanup skipped as requested. Database and input file retained.")

def main():
    # INPUT_FILENAME is no longer a global constant, but a local variable
    input_file_path = None

    # Check for command-line arguments
    if len(sys.argv) > 1:
        input_file_path = sys.argv[1]
        print(f"[*] Using input file from command line: {input_file_path}")
    else:
        # Prompt the user for the input file path
        while True:
            user_input = input("Please enter the path to the ASA connection log file (or press Enter to exit): ").strip()
            if user_input:
                input_file_path = user_input
                print(f"[*] Using input file from user prompt: {input_file_path}")
                break
            else:
                print("[!] No input file provided. Exiting.")
                sys.exit(0) # Exit if user provides empty input

    # 1. Initialize DB and Process Data
    conn = init_db()
    process_file(conn, input_file_path) # Pass the determined input_file_path

    # 2. Show Initial Reports
    print("\n\n========================================================")
    print("      INITIAL LOG ANALYSIS REPORTS        ")
    print("========================================================")

    # The full suite of required reports
    # print_database(conn) # Commented out as requested
    print_top_bytes_entries(conn)
    print_top_idle_time_entries(conn)
    print_top_uptime_entries(conn)
    print_same_interface_entries(conn)
    print_top_flag_n_entries(conn)
    print_top_initiators(conn)
    print_top_responders(conn)
    print_top_initiators_with_n_flag(conn)
    print_top_responders_with_n_flag(conn)
    print_ip_counts(conn)
    print_port_counts(conn)

    # 3. Interactive LLM Query Loop
    print("\n========================================================")
    print("      NATURAL LANGUAGE DATABASE QUERY INTERFACE        ")
    print("========================================================")

    # Re-check API key status right before the interactive loop starts
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

                # Step 3a: Get SQL from LLM
                sql_query = query_llm_for_sql(user_input)

                if sql_query:
                    # Step 3b: Execute the generated SQL
                    execute_llm_sql(conn, sql_query)

            except EOFError:
                print("\nSession ended. Goodbye!")
                break
            except Exception as e:
                print(f"\n[!] An unhandled error occurred in the loop: {e}")
                break

    # 4. Close connection and cleanup
    conn.close()
    cleanup()

if __name__ == "__main__":
    main()
