
import contextlib
import io
import os
import tempfile

import streamlit as st

from connquery import (
    init_db,
    process_file,
    print_top_bytes_entries,
    print_top_idle_time_entries,
    print_top_uptime_entries,
    print_same_interface_entries,
    print_top_flag_n_entries,
    print_ip_counts,
    print_port_counts,
    query_llm_for_sql,
    execute_llm_sql,
)


st.set_page_config(page_title="ASA Connection Analyzer", layout="wide")
st.title("ASA Connection Analyzer")
st.caption("Upload ASA connection output, review reports, and ask questions about it.")


def capture_output(function, *args, **kwargs):
    """Capture the existing CLI functions' printed output for display."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        result = function(*args, **kwargs)
    return result, buffer.getvalue()


uploaded_file = st.file_uploader(
    "Upload an ASA connection log",
    type=["txt", "log"],
)

if uploaded_file and st.button("Analyze file"):
    # process_file() expects a filename, so write the upload temporarily.
    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".log", delete=False
        ) as temp_file:
            temp_file.write(uploaded_file.getvalue())
            temp_path = temp_file.name

        # Close any database from an earlier analysis in this session.
        old_conn = st.session_state.get("conn")
        if old_conn is not None:
            old_conn.close()

        conn, _ = capture_output(init_db)
        detected_format, import_output = capture_output(
            process_file, conn, temp_path
        )

        if detected_format is None:
            conn.close()
            st.session_state.pop("conn", None)
            st.error("The file could not be parsed.")
            st.code(import_output)
        else:
            # Generated SQL must not modify the imported data.
            conn.execute("PRAGMA query_only = ON")
            st.session_state.conn = conn
            st.session_state.report_format = detected_format
            st.success(f"Imported ASA connections (format {detected_format}).")
            st.code(import_output)

    except Exception as e:
        st.error(f"Analysis failed: {e}")

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


conn = st.session_state.get("conn")

if conn is not None:
    st.header("Reports")

    reports = [
        ("Top connections by bytes", print_top_bytes_entries),
        ("Top connections by idle time", print_top_idle_time_entries),
        ("Top connections by uptime", print_top_uptime_entries),
        ("Same-interface connections", print_same_interface_entries),
        ("Connections with flag N", print_top_flag_n_entries),
        ("IP address counts", print_ip_counts),
        ("Port counts", print_port_counts),
    ]

    for title, report_function in reports:
        with st.expander(title):
            _, output = capture_output(report_function, conn)
            st.code(output, language="text")

    st.header("Ask a question")

    # For a public demo, have each visitor provide their own key rather than
    # exposing or paying for calls with a shared server-side key.
    api_key = st.text_input(
        "OpenAI API key",
        type="password",
        help="Used for this query; do not put API keys in the uploaded log.",
    )

    question = st.text_input(
        "Question",
        placeholder="Show me the top 10 source IPs by connection count",
    )

    if st.button("Run query"):
        if not api_key:
            st.warning("Enter an OpenAI API key.")
        elif not question.strip():
            st.warning("Enter a question.")
        else:
            sql, llm_output = capture_output(
                query_llm_for_sql, question, api_key
            )

            if not sql:
                st.error("Could not generate SQL.")
                st.code(llm_output)
            elif not sql.lstrip().upper().startswith("SELECT "):
                st.error("Only SELECT queries are permitted.")
            else:
                _, result_output = capture_output(
                    execute_llm_sql, conn, sql
                )
                st.subheader("Result")
                st.code(result_output, language="text")
