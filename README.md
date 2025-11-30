**Cisco ASA Connection Log Analyzer**

This Python script is a powerful tool for parsing, storing, and analyzing connection logs from Cisco ASA firewalls. It uses an SQLite database for high-performance data storage and integrates the Gemini API to allow users to query the log data using natural language, translating plain English into executable SQL.

**Features**

Multi-Format Log Parsing: Automatically detects and parses three common Cisco ASA log formats (F1, F2, F3).

SQLite Database Integration: Stores all parsed log entries in a structured SQLite database (asa_connections.db).

Initial Analysis Reports: Generates a suite of pre-defined reports on connection statistics, including:

Top connections by bytes transferred.

Top connections by idle time and uptime.

Connections where the source and destination interfaces are the same.

Top IP/Port counts.

Connections featuring NAT/XLATE flags.

Natural Language Query Interface (LLM): Connects to the Gemini API, allowing you to ask complex questions in plain English (e.g., "Show me the top 5 protocols with the most bytes transferred") and receiving the results instantly.


**Prerequisites**

**Python 3: The script requires Python 3.6 or newer.**

requests Library: For communication with the Gemini API.

Gemini API Key: Required for the natural language querying feature.


**1. Install Dependencies**

You need the requests library to make HTTP calls to the Gemini API.

pip install requests


**2. Set API Key**

The script reads your Gemini API Key from an environment variable named GEMINI_API_KEY.

Linux/macOS:

export GEMINI_API_KEY='YOUR_API_KEY_HERE'


Windows (PowerShell):

$env:GEMINI_API_KEY='YOUR_API_KEY_HERE'


(Replace YOUR_API_KEY_HERE with your actual key.)

If the key is not set, the script will run the log parsing and initial reports, but the Natural Language Query Interface will be disabled.


**Usage**

**1. Prepare Log File**

Place your Cisco ASA connection log file in the same directory as the script. You can name it anything.

**2. Run the Script**

You can run the script using its default filename (asa_conn_log.txt) or specify your file as an argument.

Default Filename (asa_conn_log.txt):

python asa_analyzer.py


Specify a Filename:

python asa_analyzer.py my_firewall_dump.txt


**3. Review Reports and Query**

The script will first:

Initialize the SQLite database (asa_connections.db).

Parse all entries from your input file.

Print the suite of initial analysis reports (top bytes, idle time, etc.).

After the initial reports, the Natural Language Query Interface will start:

========================================================
      NATURAL LANGUAGE DATABASE QUERY INTERFACE        
========================================================
[*] LLM interface is active.
You can now ask questions about the data using natural language.
Query > show me the total number of connections for IP address 10.1.1.5
[*] Sending query to LLM...
--- LLM QUERY RESULT ---
COUNT(*)  
----------
45        
----------
[*] Query executed: SELECT COUNT(*) FROM connections WHERE ip_addr1 = '10.1.1.5' OR ip_addr2 = '10.1.1.5'
[*] Total rows returned: 1

Query > exit
Session ended. Goodbye!


Type exit or quit to end the interactive session.



The Gemini LLM uses the following schema to generate accurate SQL queries.

Column  Name                  Type                     Description      
id                            INTEGER                  Primary Key
protocol                      TEXT                     TCP, UDP, ICMP, etc.
interface1                    TEXT                     Source Interface Name (e.g., inside)
ip_addr1                      TEXT                     Original Source IP Address
port1                         INTEGER                  Original Source Port
xlated_ip1                    TEXT                     Translated Source IP (NAT/XLATE)
xlated_port1                  INTEGER                  Translated Source Port
interface2                    TEXT                     Destination Interface Name (e.g., outside)
ip_addr2                      TEXT                     Original Destination IP Address
port2                         INTEGER                  Original Destination Port
xlated_ip2                    TEXT                     Translated Destination IP (NAT/XLATE)
xlated_port2                  INTEGER                  Translated Destination Port
idle_time                     TEXT                     Time since last activity (e.g., 0:02:15)
uptime                        TEXT                     Total connection duration (e.g., 1h5m2s)
bytes_transferred             INTEGER                  Total bytes for the connection
flags                         TEXT                     Connection flags (e.g., UR, N, P)
initiator_ip                  TEXT                     IP that initiated the connection (Format 2 only)
responder_ip                  TEXT                     IP that responded to the connection (Format 2 only)







