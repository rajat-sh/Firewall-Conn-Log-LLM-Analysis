


# 🛡️ Cisco ASA Firewall AI Agent

A Python-based AI tool that parses massive Cisco ASA firewall connection logs, structures them into a local SQLite database, and allows you to analyze your network traffic using natural language queries. 

Powered by **OpenAI** and **LangChain**, this tool translates English questions into complex SQL queries, executes them against your log data, and returns human-readable answers along with the exact SQL used.

## ✨ Features
- **Memory-Optimized Parsing**: Handles extremely large (1GB+) log files effortlessly using a generator-based streaming architecture.
- **Natural Language Interface**: Ask questions like *"Which IP transferred the most bytes?"* or *"List all connections dropped on port 443."*
- **Dual Interfaces**: Includes a lightning-fast Command Line Interface (CLI) and a beautiful, interactive Streamlit Web App.
- **Enterprise Ready**: Built-in support for bypassing strict corporate SSL/TLS packet inspection.

---

## ⚙️ Installation & Setup

**Prerequisites:**
- Python 3.8 or higher installed on your system.
- An [OpenAI API Key](https://platform.openai.com/api-keys).

**1. Clone the repository:**
```bash
git clone https://github.com/YourUsername/asa-log-analyzer.git
cd asa-log-analyzer
```

**2. Create and activate a virtual environment (Recommended):**
* On Windows:
  ```bash
  python -m venv venv
  venv\Scripts\activate
  ```
* On Mac/Linux:
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

**3. Install the required libraries:**
```bash
pip install -r requirements.txt
```

**4. Configure your API Key:**
Rename the `.env.example` file to `.env` and paste your OpenAI API key inside:
```text
OPENAI_API_KEY=sk-your-secret-api-key-here
```

---

## 🚀 How to Use

You can choose to run this tool as a Web Application or as a Command Line Interface (CLI).

### Option A: The Web Application (Streamlit)
Provides a modern, interactive User Interface directly in your web browser. It allows you to drag-and-drop log files and view static analysis reports alongside an AI chat interface.

**To start the web app:**
```bash
streamlit run web_app.py
```
1. A new tab will automatically open in your web browser (usually at `http://localhost:8501`).
2. Upload your `.log` or `.txt` file using the sidebar.
3. Once processed, you can expand the initial reports or start chatting with the AI!

### Option B: The Command Line Interface (CLI)
A fast, lightweight terminal interface perfect for quick lookups or running on remote servers without a graphical interface.

**To start the CLI app:**
```bash
python cli_app.py
```
1. The terminal will prompt you to provide the path to your log file (e.g., `C:\logs\asa.txt`).
2. The script will parse the file, print initial statistical reports, and drop you into an interactive `Query >` prompt.
3. Type your natural language questions. Type `quit` to securely clean up the database and exit.

---

## 🔧 Troubleshooting

**`[SSL: CERTIFICATE_VERIFY_FAILED]` Error**
If you are on a corporate network with a firewall that inspects HTTPS traffic, Python might block the connection to OpenAI. 
- **Web App**: Check the "Bypass SSL Verification" box in the sidebar before uploading your file.
- **CLI App**: Run the script with the ignore-ssl flag: `python cli_app.py --ignore-ssl`

---

## 📁 Repository Structure
- `cli_app.py` - The core logic and terminal-based application.
- `web_app.py` - The Streamlit-based graphical user interface.
- `requirements.txt` - Python dependencies needed to run the apps.
- `.env.example` - Template for configuring environment variables.
```  
 
