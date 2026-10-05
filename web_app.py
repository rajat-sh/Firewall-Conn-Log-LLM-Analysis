import streamlit as st
import os
import tempfile
import sqlite3
import httpx
import io
from contextlib import redirect_stdout
from dotenv import load_dotenv
import warnings
# Hide LangChain Deprecation Warnings from the console
warnings.filterwarnings("ignore", category=DeprecationWarning) # <-- Add this


# LangChain imports
from langchain_community.utilities.sql_database import SQLDatabase
from langchain_openai import ChatOpenAI
from langchain_community.agent_toolkits import create_sql_agent

# Import logic AND reporting functions from cli_app.py
from cli_app import (
    process_file, 
    CUSTOM_ASA_PREFIX, 
    LLM_MODEL,
    print_top_bytes_entries,
    print_top_idle_time_entries,
    print_same_interface_entries,
    print_top_flag_n_entries,
    print_ip_counts,
    print_port_counts
)

# Define the schema directly here for the temporary web databases
CONNECTIONS_SCHEMA_SQL = '''
    CREATE TABLE IF NOT EXISTS connections (
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
        reverse_time_last_max TEXT,
        idle_seconds INTEGER,
        uptime_seconds INTEGER
    )
'''

# --- 1. PAGE SETUP ---
st.set_page_config(page_title="ASA Firewall AI Agent", page_icon="🛡️", layout="wide")
st.title("🛡️ Cisco ASA Firewall AI Agent")
st.markdown("Upload your ASA connection log file and ask questions in natural language.")

# Load environment variables
load_dotenv(override=True)

# --- 2. SESSION STATE MANAGEMENT ---
if "messages" not in st.session_state:
    st.session_state["messages"] = [{"role": "assistant", "content": "Hello! Please upload an ASA log file in the sidebar. If you provide an API key, you can chat with me here!"}]

if "db_path" not in st.session_state:
    st.session_state["db_path"] = None

if "agent" not in st.session_state:
    st.session_state["agent"] = None

if "initial_report" not in st.session_state:
    st.session_state["initial_report"] = None

# --- 3. SIDEBAR: CONFIGURATION & UPLOAD ---
with st.sidebar:
    st.header("Configuration")
    
    env_api_key = os.environ.get("OPENAI_API_KEY", "")
    
    api_key = st.text_input("OpenAI API Key (Optional)", value=env_api_key, type="password", help="Leave blank if you only want the static reports without AI chat.")
    
    ignore_ssl = st.checkbox("Bypass SSL Verification", value=True,help="Check this if you are on a corporate network and receive Certificate errors.")
    
    st.divider()
    st.header("File Upload")
    
    # REMOVED the type=["txt", "log"] restriction so it accepts ANY file extension
    uploaded_file = st.file_uploader("Upload ASA Log File (Any extension)")

    if st.button("Process File") and uploaded_file:
        with st.spinner("Processing file... Please wait."):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp_log:
                tmp_log.write(uploaded_file.getvalue())
                tmp_log_path = tmp_log.name
            
            fd, tmp_db_path = tempfile.mkstemp(suffix='.db')
            os.close(fd)
            
            conn = sqlite3.connect(tmp_db_path)
            conn.execute('DROP TABLE IF EXISTS connections')
            conn.execute(CONNECTIONS_SCHEMA_SQL)
            conn.commit()

            format_type = process_file(conn, tmp_log_path)
            
            if format_type:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM connections")
                row_count = cursor.fetchone()[0]
                
                # --- GENERATE STATIC REPORTS ---
                f = io.StringIO()
                with redirect_stdout(f):
                    print_top_bytes_entries(conn)
                    print_top_idle_time_entries(conn)
                    print_same_interface_entries(conn) 
                    print_top_flag_n_entries(conn)
                    print_ip_counts(conn, 50)
                    print_port_counts(conn, 50)
                
                st.session_state["initial_report"] = f.getvalue()
                
                # --- CONDITIONALLY SETUP AGENT ---
                if api_key:
                    http_client = httpx.Client(verify=False) if ignore_ssl else None
                    sql_db = SQLDatabase.from_uri(f"sqlite:///{tmp_db_path}")
                    
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

                    st.session_state["agent"] = agent_executor
                    st.session_state["db_path"] = tmp_db_path
                    st.success(f"Successfully processed {row_count} records! AI Chat is enabled.")
                else:
                    st.session_state["agent"] = None
                    st.success(f"Successfully processed {row_count} records! Generated Static Reports only (No API Key provided).")
            else:
                st.error("Could not detect a valid ASA log format in this file.")
            
            conn.close()
            os.remove(tmp_log_path)

# --- 4. MAIN UI & CHAT INTERFACE ---

if st.session_state["initial_report"]:
    with st.expander("📊 View Initial Log Analysis Reports", expanded=False):
        st.code(st.session_state["initial_report"], language="text")

for msg in st.session_state["messages"]:
    st.chat_message(msg["role"]).write(msg["content"])

if user_question := st.chat_input("Ask a question about your firewall logs..."):
    
    st.chat_message("user").write(user_question)
    st.session_state["messages"].append({"role": "user", "content": user_question})
    
    if st.session_state["agent"] is None:
        error_msg = "LLM Chat is disabled because no OpenAI API Key was provided. Please add your key in the sidebar and re-process the file to chat!"
        st.chat_message("assistant").write(error_msg)
        st.session_state["messages"].append({"role": "assistant", "content": error_msg})
    else:
        with st.chat_message("assistant"):
            with st.spinner("Analyzing database..."):
                try:
                    response = st.session_state["agent"].invoke({"input": user_question})
                    answer = response["output"]
                    st.write(answer)
                    st.session_state["messages"].append({"role": "assistant", "content": answer})
                except Exception as e:
                    st.error(f"An error occurred: {e}")
