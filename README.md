# 🛡️ CyberGuard Security Scanner

CyberGuard is a sleek, modern web application designed to analyze potentially malicious URLs and files. It provides a clean, user-friendly interface for interacting with the powerful VirusTotal API, delivering real-time threat analysis with a professional, dark-mode "cyber" aesthetic.


---

## ✨ Features

*   **Dual Analysis Modes:** Scan both URLs and files through a simple tabbed interface.
*   **Modern "Glassmorphism" UI:** A cool, frosted-glass look with a dark-mode theme and glowing accents.
*   **Real-time Results:** Leverages the VirusTotal API to check items against over 70 antivirus scanners and blocklisting services.
*   **Clear & Concise Verdicts:** Get an immediate, color-coded "Safe" or "High Risk" verdict based on the scan results.
*   **Secure API Key Handling:** Uses a `.env` file and `.gitignore` to keep your API key 100% safe and off of GitHub.
*   **Built with Python & Flask:** A lightweight and powerful backend.

---

## 🛠️ Tech Stack

*   **Backend:** Python 3, Flask
*   **Frontend:** HTML5, CSS3
*   **External API:** [VirusTotal Public API v3](https://developers.virustotal.com/reference)
*   **Security:** `python-dotenv` for secure environment variable management.

---

## 🚀 Getting Started

Follow these instructions to get a local copy up and running on your machine.

### Prerequisites

You must have the following installed on your system:
*   [Python 3](https://www.python.org/downloads/)
*   `pip` (Python's package installer, which usually comes with Python)

### Installation & Setup

1.  **Clone the repository**
    ```sh
    git clone https://github.com/your-username/pro_scanner.git
    ```

2.  **Navigate to the project directory**
    ```sh
    cd pro_scanner
    ```

3.  **Create a virtual environment** (Highly Recommended)
    This creates an isolated space for your project's packages.
    ```sh
    # On Windows
    py -m venv venv

    # On macOS/Linux
    python3 -m venv venv
    ```

4.  **Activate the virtual environment**
    ```sh
    # On Windows
    .\venv\Scripts\activate

    # On macOS/Linux
    source venv/bin/activate
    ```

5.  **Install the required packages**
    ```sh
    pip install -r requirements.txt
    ```
    *(Note: If you don't have a `requirements.txt` file yet, create one with `pip freeze > requirements.txt` after installing the packages mentioned in the next step).*

6.  **Install the necessary libraries** (if you don't have a `requirements.txt`)
    ```sh
    pip install Flask requests python-dotenv
    ```

---

## ⚙️ Configuration

This project requires a VirusTotal API key to function. Your key is kept secure locally and will not be pushed to GitHub.

1.  **Get your API Key:**
    *   Sign up for a free account on the [VirusTotal Community](https://www.virustotal.com/gui/join-us).
    *   Once logged in, navigate to your profile in the top-right to find your **API Key**.

2.  **Create a `.env` file:**
    In the main project directory, create a new file named **exactly** `.env`.

3.  **Add your API key to the `.env` file:**
    Open the `.env` file and add the following line, replacing `YOUR_KEY_HERE` with your actual key:
    ```
    VIRUSTOTAL_API_KEY="YOUR_KEY_HERE"
    ```

The `.gitignore` file is already configured to prevent this file from ever being uploaded.

---

## 🕹️ Usage

1.  **Run the Flask application**
    Make sure your virtual environment is activated, then run:
    ```sh
    python app.py
    ```

2.  **Open the application in your browser**
    Navigate to the following address in your web browser:
    ```
    http://127.0.0.1:5000
    ```

You can now use the interface to scan URLs and files!

---
