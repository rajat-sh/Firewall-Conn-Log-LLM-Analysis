

This README covers:
*   Project overview
*   Features
*   Prerequisites
*   Installation
*   Configuration
*   Usage (with examples)
*   Supported Log Formats
*   LLM Integration details
*   Troubleshooting common issues
*   License

---

# ConnQuery AI: Cisco FTD Connection Table Analyzer

A Python tool designed to parse and analyze Cisco FTD (Firepower Threat Defense) connection table logs (`show conn`,'show conn long','show conn detail' output). It stores the parsed data in a local SQLite database and provides various statistical reports. Additionally, it features an experimental Natural Language Query (NLQ) interface, powered by Google's Gemini API, allowing users to query their connection data using plain English.

## Table of Contents

-   [ConnQuery AI: Cisco FTD Connection Table Analyzer](#connquery-ai-cisco-ftd-connection-table-analyzer)
    -   [Table of Contents](#table-of-contents)
    -   [Features](#features)
    -   [Prerequisites](#prerequisites)
    -   [Installation](#installation)
    -   [Configuration](#configuration)
    -   [Usage](#usage)
        -   [Running the Script](#running-the-script)
        -   [Initial Reports](#initial-reports)
        -   [Natural Language Query Interface](#natural-language-query-interface)
    -   [Supported Log Formats](#supported-log-formats)
    -   [LLM Integration Details](#llm-integration-details)
    -   [Troubleshooting](#troubleshooting)
    -   [License](#license)

## Features

*   **Log Parsing:** Automatically detects and parses three different formats of Cisco FTD `show conn` output (show conn, show conn long, and show conn detail), including multi-line entries).
*   **SQLite Database:** Stores all parsed connection data in a local `asa_connections.db` SQLite database for efficient querying.
*   **Predefined Reports:** Generates a suite of initial reports, including:
    *   Top connections by bytes transferred.
    *   Top connections by idle time.
    *   Top connections by uptime.
    *   Connections where source and destination interfaces are the same.
    *   Connections with specific flags (e.g., 'N' for snort inspected).
    *   Counts of IP addresses, ports, initiators, and responders.
*   **Natural Language Query (NLQ) Interface:** Allows users to ask questions about their connection data in plain English, which is then converted into SQL queries using the Google Gemini API.
*   **Extensible:** The SQLite database makes it easy to add custom queries or integrate with other analysis tools.

## Prerequisites

Before running the script, ensure you have the following:

*   **Python 3.x:** (Tested with Python 3.8+)
*   **`requests` library:** For communicating with the Google Gemini API.
    ```bash
    pip install requests
    ```
*   **Google Gemini API Key:** You'll need an API key from Google Cloud. Set this as an environment variable named `GEMINI_API_KEY`.
    *   **macOS/Linux:**
        ```bash
        export GEMINI_API_KEY='YOUR_API_KEY_HERE'
        ```
    *   **Windows (CMD):**
        ```cmd
        set GEMINI_API_KEY=YOUR_API_KEY_HERE
        ```
    *   **Windows (PowerShell):**
        ```powershell
        $env:GEMINI_API_KEY='YOUR_API_KEY_HERE'
        ```
    (Replace `'YOUR_API_KEY_HERE'` with your actual API key.)

## Installation

1.  **Clone the repository:**
    
    git clone https://github.com/rajat-sh/Firewall-Conn-Log-LLM-Analysis.git
    cd ConnQuery_AI
    

2.  **Install Python dependencies:**
    
    pip install -r requirements.txt # (assuming you create a requirements.txt with 'requests')
    # OR
    pip install requests
    

3.  **Set your Google Gemini API Key** as described in the [Prerequisites](#prerequisites) section.

## Configuration

You can adjust the following parameters directly in the `ConnQuery_AI.py` script:

*   `DB_NAME`: Name of the SQLite database file (default: `'asa_connections.db'`).
*   `INPUT_FILENAME`: Default log file name if not provided as a command-line argument (default: `'asa_conn_log.txt'`).
*   `BATCH_SIZE`: Number of records to insert into the database at once (default: `5000`).
*   `LLM_MODEL`: The specific Gemini model used for NLQ (default: `'gemini-2.5-flash-preview-09-2025'`).
*   `LLM_API_URL`: The base URL for the Gemini API.

## Usage

### Running the Script

You can run the script by providing the path to your FTD connection log file as a command-line argument:

```bash
python ConnQuery_AI.py /path/to/your/ftd_conn_log.txt
```



### Initial Reports

After successfully parsing the log file, the script will automatically generate and print a series of predefined analytical reports to the console. The detailed "Database Entries (Detailed View)" table is intentionally omitted from the initial reports for brevity, but other summary reports are displayed.
 * Top 50 Connections by Bytes Transferred (Descending)
 * Top 50 Connections by Idle Time (Descending)
 * Top 50 Connections by Uptime (Descending)
 * Top 50 Same-Interface Connections by Bytes Transferred (Descending)
 * Top 50 Connections with Flag 'N' by Bytes Transferred (Descending)
 * Top 50 Initiator IPs by Connection Count
 * Top 50 Responder IPs by Connection Count
 * Top 50 Initiator IPs (Flags containing 'N')
 * Top 50 Responder IPs (Flags containing 'N')
 * IP Address Counts (Descending, Top 50)
 * Port Counts (Descending, Top 50)

### Natural Language Query Interface

Following the initial reports, the script enters an interactive mode where you can ask questions about your connection data using natural language.

```
========================================================
      NATURAL LANGUAGE DATABASE QUERY INTERFACE        
========================================================
[*] LLM interface is active.
You can now ask questions about the data using natural language.
Try queries like: 'show me the top 10 protocols by count',
or 'list all connections where the initiator is 192.168.2.20'.
Type 'exit' or 'quit' to end the session.

Query > show me the top 5 destination IP addresses by bytes transferred
--- LLM QUERY RESULT ---
ip_addr2               SUM(bytes_transferred)
----------------------------------------------
192.168.4.23           500
192.168.2.80           130
192.168.2.20           129
192.168.1.38           154
----------------------------------------------
[*] Query executed: SELECT ip_addr2, SUM(bytes_transferred) FROM connections GROUP BY ip_addr2 ORDER BY SUM(bytes_transferred) DESC LIMIT 5
[*] Total rows returned: 4

Query > list all UDP connections from 192.168.4.23
--- LLM QUERY RESULT ---
id  protocol  interface1  ip_addr1      port1  xlated_ip1    xlated_port1  interface2  ip_addr2      port2  xlated_ip2    xlated_port2  idle_time  uptime  bytes_transferred  flags  initiator_ip  responder_ip
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
1   UDP       outside     4.2.2.2       200    4.2.2.2       200           inside      192.168.4.23  1321   10.48.26.235  1321          12s        12s     100                -      192.168.4.23  4.2.2.2
3   UDP       outside     4.2.2.2       100    4.2.2.2       100           inside      192.168.4.23  2105   10.48.26.235  2105          1m36s      1m36s   100                -      192.168.4.23  4.2.2.2
5   UDP       outside     4.2.2.2       200    4.2.2.2       200           inside      192.168.4.23  1314   10.48.26.235  1314          19s        19s     100                -      192.168.4.23  4.2.2.2
7   UDP       outside     4.2.2.2       200    4.2.2.2       200           inside      192.168.4.23  1307   10.48.26.235  1307          26s        26s     100                -      192.168.4.23  4.2.2.2
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
[*] Query executed: SELECT * FROM connections WHERE protocol = 'UDP' AND initiator_ip = '192.168.4.23'
[*] Total rows returned: 4

Query > exit
Session ended. Goodbye!
```

## Supported Log Formats

The script is designed to intelligently parse different variations of Cisco FTD `show conn` output. It attempts to detect the format based on specific patterns in the lines.

**show conn long   (Most Detailed - with Translated IPs and Initiator/Responder):**
Characterized by `(TranslatedIP/TranslatedPort)` and often includes an `Initiator:` and `Responder:` line.
Example:
```
UDP outside: 4.2.2.2/200 (4.2.2.2/200) inside: 192.168.4.23/1321 (10.48.26.235/1321), flags - , idle 12s, uptime 12s, timeout 2m0s, bytes 100, xlate id 0x7fcbc5a1e580, flow id 33782708, Rx-RingNum invalid, Internal-Data invalid
  Initiator: 192.168.4.23, Responder: 4.2.2.2
```

**show conn (IP:Port notation):**
Characterized by `IP:Port` notation for source/destination and `idle` time.
Example:
```
TCP internet  41.13.0.207:59737 INTERNAL-NETWORK  172.18.222.186:443, idle 0:52:09, bytes 132619, flags UfIO N1
```

**show conn detail (IP/Port notation, without translated IPs, with Initiator/Responder):**
Characterized by `IP/Port` notation (without parentheses for translated IPs) and may include `Initiator:` and `Responder:` lines.
Example:
```
TCP outside:1.1.1.1/1234 inside:2.2.2.2/5678, flags U, idle 1m2s, uptime 1m2s, bytes 12345
  Initiator: 1.1.1.1, Responder: 2.2.2.2
```


## LLM Integration Details

The Natural Language Query (NLQ) interface uses the Google Gemini API to translate your English questions into SQLite SQL queries.

*   **API Key:** Ensure your `GEMINI_API_KEY` environment variable is correctly set. Without it, the NLQ interface will be disabled.
*   **Model:** The script uses `gemini-2.5-flash-preview-09-2025`. As this is a preview model, its behavior and availability might change.
*   **Safety Filters:** Google's LLMs include safety filters. If your query is flagged as potentially unsafe or inappropriate, the LLM might refuse to generate a response, leading to an error or an empty result. The script includes debugging output to help identify such cases.
*   **Deterministic Output:** The `temperature` setting for the LLM is set to `0.0` to encourage deterministic (consistent) SQL output for the same query.

## Troubleshooting

*   **`SyntaxError: unterminated string literal`**:
    *   **Cause:** This usually happens in Python when a string literal (like one defined with `"` or `'`) contains an unescaped quote of the same type.
    *   **Solution:** Ensure any multi-line strings, especially in `print` statements, use triple quotes (e.g., `"""Your multi-line string here"""`) to avoid this. The provided code has already been updated to handle this in the API key warning message.

*   **Empty Output / `[*] Successfully processed 0 entries`**:
    *   **Cause:** The script failed to correctly identify the log format or parse any connection records. This can happen if the log file contains unexpected header information or a format not fully covered by the current parsing logic.
    *   **Solution:**
        1.  **Verify Input File:** Double-check that the input file (`asa_conn_log.txt` or the one you provide) actually contains connection records similar to the examples in [Supported Log Formats](#supported-log-formats).
        2.  **Check Debug Output:** The script now includes `DEBUG: Attempting format detection for line X: '...'` messages. Review these to see if the script correctly identifies the format of your first connection entry. If it's detecting the wrong format (e.g., Format 2 for a Format 3 log), the detection regexes might need further fine-tuning for your specific log variation.
        3.  **Inspect Parsing Errors:** Look for `[!] Format X Parsing Error` messages in the output. These will indicate which parsing function failed and for which record, helping pinpoint the exact regex or data extraction issue.

*   **`KeyError: 'parts'` or other LLM-related parsing errors**:
    *   **Cause:** The LLM API returned a response that the script didn't expect, often due to safety filters, an empty generation, or an unexpected JSON structure.
    *   **Solution:** The script now prints the `Full LLM Response for debugging` when this occurs. Examine this JSON output:
        *   If `candidates` is empty or `promptFeedback` shows `safetyRatings`, your query might have triggered safety filters. Try rephrasing your question.
        *   If the JSON structure is different, the script's `sql_query = result['candidates'][0]['content']['parts'][0]['text'].strip()` line might need adjustment based on the actual API response format.

*   **`[!] The 'requests' library is not installed.`**:
    *   **Cause:** The `requests` Python library is missing.
    *   **Solution:** Run `pip install requests`.

*   **`[!] WARNING: GEMINI_API_KEY environment variable not found.`**:
    *   **Cause:** The `GEMINI_API_KEY` environment variable is not set or is not accessible to the script.
    *   **Solution:** Set the environment variable as described in the [Prerequisites](#prerequisites) section.

## License



 
