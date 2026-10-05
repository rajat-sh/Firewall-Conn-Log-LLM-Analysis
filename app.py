
import streamlit as st
import os
import tempfile
import sqlite3
import httpx
from dotenv import load_dotenv

# LangChain imports
from langchain_community.utilities.sql_database import SQLDatabase
from langchain_openai import ChatOpenAI
from langchain_community.agent_toolkits import create_sql_agent

# We import the core logic from your existing CLI script to avoid repeating code (DRY principle)
from cli_app import (
    process_file, 
    CONNECTIONS_SCHEMA_SQL, 
    CUSTOM_ASA_PREFIX, 
    LLM_MODEL
)

# --- 1. PAGE SETUP ---
st.set_page_config(page_title="ASA Firewall AI Agent", page_icon="🛡️", layout="wide")
st.title("🛡️ Cisco ASA Firewall AI Agent")
st.markdown("Upload your ASA connection log file and ask questions in natural language.")

# Load environment variables
load_dotenv(override=True)

# --- 2. SESSION STATE MANAGEMENT ---
# Streamlit re-runs the script from top to bottom on every user interaction.
# We use st.session_state to remember things across these re-runs (like the database path and chat history).

if "messages" not in st.session_state:
    st.session_state["messages"] = [{"role": "assistant", "content": "Hello! Please upload an ASA log file in the sidebar, then ask me anything about the network traffic."}]

if "db_path" not in st.session_state:
    st.session_state["db_path"] = None

if "agent" not in st.session_state:
    st.session_state["agent"] = None

# --- 3. SIDEBAR: CONFIGURATION & UPLOAD ---
with st.sidebar:
    st.header("Configuration")
    
    # Allow user to input API key if it's not in the environment
    env_api_key = os.environ.get("OPENAI_API_KEY", "")
    api_key = st.text_input("OpenAI API Key", value=env_api_key, type="password", help="Requires an OpenAI API Key (sk-...)")
    
    ignore_ssl = st.checkbox("Bypass SSL Verification", help="Check this if you are on a corporate network and receive Certificate errors.")
    
    st.divider()
    st.header("File Upload")
    uploaded_file = st.file_uploader("Upload ASA Log File (.txt or .log)", type=["txt", "log"])

    if st.button("Process File") and uploaded_file and api_key:
        with st.spinner("Processing file... Please wait."):
            # Save the uploaded file to a temporary location on disk
            with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp_log:
                tmp_log.write(uploaded_file.getvalue())
                tmp_log_path = tmp_log.name
            
            # Create a unique temporary SQLite database for this user's session
            fd, tmp_db_path = tempfile.mkstemp(suffix='.db')
            os.close(fd)
            
            # Initialize the database schema
            conn = sqlite3.connect(tmp_db_path)
            conn.execute('DROP TABLE IF EXISTS connections')
            conn.execute(CONNECTIONS_SCHEMA_SQL)
            conn.commit()

            # Process the log file using the logic from cli_app.py
            format_type = process_file(conn, tmp_log_path)
            
            if format_type:
                # Count records for UI feedback
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM connections")
                row_count = cursor.fetchone()[0]
                
                # Setup LangChain Agent
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

                # Save the agent and DB path to session state
                st.session_state["agent"] = agent_executor
                st.session_state["db_path"] = tmp_db_path
                
                st.success(f"Successfully processed {row_count} records! (Format {format_type})")
            else:
                st.error("Could not detect a valid ASA log format in this file.")
            
            # Clean up the temporary log file
            conn.close()
            os.remove(tmp_log_path)

# --- 4. MAIN CHAT INTERFACE ---

# Display all previous chat messages
for msg in st.session_state["messages"]:
    st.chat_message(msg["role"]).write(msg["content"])

# Capture new user input
if user_question := st.chat_input("Ask a question about your firewall logs..."):
    
    # 1. Add user message to UI and session state
    st.chat_message("user").write(user_question)
    st.session_state["messages"].append({"role": "user", "content": user_question})
    
    # 2. Check if the agent is ready
    if st.session_state["agent"] is None:
        error_msg = "Please upload and process a file in the sidebar before asking questions."
        st.chat_message("assistant").write(error_msg)
        st.session_state["messages"].append({"role": "assistant", "content": error_msg})
    else:
        # 3. Generate response using LangChain
        with st.chat_message("assistant"):
            with st.spinner("Analyzing database..."):
                try:
                    response = st.session_state["agent"].invoke({"input": user_question})
                    answer = response["output"]
                    st.write(answer)
                    st.session_state["messages"].append({"role": "assistant", "content": answer})
                except Exception as e:
                    st.error(f"An error occurred: {e}")
