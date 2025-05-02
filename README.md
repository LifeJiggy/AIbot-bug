
# Bug Bounty AI Assistant

This is an AI-powered assistant designed to help bug bounty hunters, security researchers (red and blue teams), and anyone interested in web, network, and application security. It leverages the Gemini API to answer your questions related to reconnaissance, enumeration, mapping, vulnerability detection, exploitation, and general security concepts.

## Features

* **Intelligent Responses:** Get comprehensive and informative answers to your security-related questions powered by the Gemini AI model.
* **Role-Aware Assistance:** Optionally specify your role (e.g., bug bounty hunter, red teamer) to get more tailored advice.
* **Tool Suggestions:** The AI can suggest relevant security tools along with basic command-line examples and explanations of their use.
* **Contextual Conversations:** The assistant remembers previous questions in your current session, allowing for more natural follow-up questions.
* **Knowledgeable:** The AI considers information from reputable security resources like OWASP and CVE databases in its responses.
* **Configurable Model:** You can specify which Gemini model to use via a command-line argument.
* **User-Friendly Output:** Responses are formatted using Markdown for better readability, including code blocks for commands.
* **Input Validation:** Basic checks to ensure you don't send empty questions.

## Prerequisites

* **Python 3.6 or higher:** Make sure you have Python installed on your system.
* **`pip` package installer:** Usually comes with Python.
* **Google Gemini API Key:** You'll need to obtain an API key from the Google AI Studio website ([https://ai.google.dev/](https://ai.google.dev/)).
* **`google-generativeai` library:** This Python library is used to interact with the Gemini API.

## Installation

1.  **Clone the repository (via GitHub):**
    ```bash
    git clone [YOUR_REPOSITORY_URL]
    cd [REPOSITORY_DIRECTORY]
    ```

2.  **Install the required Python library:**
    ```bash
    pip install google-generativeai
    ```

3.  **Set up your Gemini API Key:**
    The script relies on an environment variable named `GEMINI_API_KEY` to access your API key securely. You can set this in your terminal before running the script:

    * **Linux/macOS:**
        ```bash
        export GEMINI_API_KEY="YOUR_API_KEY_HERE"
        ```
        (You might want to add this line to your shell configuration file (e.g., `.bashrc`, `.zshrc`) to make it permanent.)
    * **Windows (Command Prompt):**
        ```bash
        set GEMINI_API_KEY="YOUR_API_KEY_HERE"
        ```
    * **Windows (PowerShell):**
        ```powershell
        $env:GEMINI_API_KEY = "YOUR_API_KEY_HERE"
        ```
        (For a permanent setting, use the System Environment Variables as described earlier.)

    **Important:** Replace `"YOUR_API_KEY_HERE"` with your actual Gemini API key. **Do not hardcode your API key directly in the script.**

## Usage

1.  **Navigate to the directory containing the script in your terminal.**
2.  **Run the script:**
    ```bash
    python Gemini.py
    ```

3.  **Follow the prompts:**
    * The assistant will greet you and ask for your security-related questions.
    * Type your question and press Enter.
    * You will be prompted to optionally enter your role (bug bounty hunter, red teamer, etc.). Leave it blank for a general response.
    * The AI's response will be displayed.
    * You can continue asking more questions; the assistant will maintain context within the current session.
    * Type `exit` to quit the assistant.

### Optional: Specifying the Gemini Model

You can specify a different Gemini model to use by using the `--model` command-line argument:

```bash
python Gemini.py --model gemini-pro
python Gemini.py --model gemini-2.0-flash
# ... other available models




