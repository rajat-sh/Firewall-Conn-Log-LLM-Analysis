# 🛡️ Cisco ASA Firewall AI Agent

A robust, memory-optimized Python tool designed to parse massive Cisco ASA firewall connection logs. It structures the data into a local SQLite database and provides dual analysis modes: **Lightning-fast Static Statistical Reports** and an **OpenAI-powered Natural Language Chat Interface**.

Whether you just need a quick summary of top talkers, or you want to ask complex questions like *"Which IP transferred the most bytes on port 443?"*, this tool handles it effortlessly.

## ✨ Key Features
- **Memory-Optimized Parsing:** Uses a generator-based streaming architecture to process extremely large (1GB+) log files using almost zero RAM.
- **Optional AI Integration:** Don't have an OpenAI API key? No problem! The tool defaults to generating powerful static reports (Top IPs, Top Ports, Highest Bytes, Idle Times) completely offline.
- **Natural Language Querying:** Feed the AI your API key, and it translates English questions into complex SQL, queries your database locally, and explains the results.
- **Dual Interfaces:** Choose between a lightweight Command Line Interface (CLI) or a modern, interactive Web App (Streamlit).
- **Enterprise-Ready:** Built-in SSL Verification bypass ensures the tool works seamlessly behind strict corporate proxies and firewalls.

---

## ⚙️ Installation & Setup

**Prerequisites:**
- Python 3.8 or higher installed on your system.
- *(Optional)* An [OpenAI API Key](https://platform.openai.com/api-keys) if you want to use the AI chat features.

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

**4. Configure your API Key (Optional):**
Rename the `.env.example` file to `.env` and paste your OpenAI API key inside:
```text
OPENAI_API_KEY=sk-your-secret-api-key-here
```

---

## 🚀 How to Use

### Option A: The Web Application (Streamlit)
A modern, interactive User Interface directly in your web browser. Features drag-and-drop file uploads (accepts any file extension) and interactive chat.

**To start the web app:**
```bash
streamlit run web_app.py
```
1. A new tab will automatically open in your web browser (usually at `http://localhost:8501`).
2. *(Optional)* Provide your API key in the sidebar if it isn't in your `.env` file.
3. Upload your log file and click **Process File**.
4. View the static reports in the dropdown, or chat with the AI!

### Option B: The Command Line Interface (CLI)
A fast, lightweight terminal interface perfect for massive files (2GB+) or running on headless servers.

**To start the CLI app:**
```bash
python cli_app.py
```
1. You will be prompted for an API key. (Press `Enter` to skip and run Static Analysis only).
2. Provide the local path to your log file (e.g., `C:\logs\asa.txt`).
3. The script will parse the file, print statistical reports, and drop you into an interactive `Query >` prompt (if an API key was provided). Type `quit` to exit safely.

---

## 🔧 Advanced Configuration & Troubleshooting

**Handling Massive Files in the Web UI (200MB+ Limit)**
By default, Streamlit limits uploads to 200MB to protect your browser's memory. To analyze 1GB+ files in the Web UI, you can bypass this limit by starting the app with this command:
```bash
streamlit run web_app.py --server.maxUploadSize 2048
```
*(Note: Uploading 2GB files via a web browser requires significant RAM. If your browser crashes, simply use the CLI version (`python cli_app.py`), which reads directly from your hard drive with zero memory overhead!)*

**`[SSL: CERTIFICATE_VERIFY_FAILED]` Error**
If you are on a corporate network that inspects HTTPS traffic, Python may block the connection to OpenAI. 
- **Web App**: Check the "Bypass SSL Verification" box in the sidebar (Checked by default).
- **CLI App**: The CLI automatically bypasses this behind the scenes for you.

**`ModuleNotFoundError: No module named 'torch'` (Console Spam)**
When running the Web App, you may see red warnings in your terminal about missing the `torch` module. **You can safely ignore these.** Streamlit aggressively scans installed libraries (like LangChain), which optionally look for PyTorch. Since we are using cloud APIs, PyTorch is not required and this warning does not affect the app.

---

## 📁 Repository Structure
- `cli_app.py` - The core parsing logic and terminal-based application.
- `web_app.py` - The Streamlit-based graphical user interface.
- `requirements.txt` - Python dependencies.
- `.env.example` - Template for configuring environment variables.
```  
 
