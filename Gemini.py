import google.generativeai as genai
import os
import json
import argparse  # For command-line arguments

# Default model (can be overridden via command line)
DEFAULT_MODEL = 'gemini-2.5-pro-exp-03-25'

# Ensure the environment variable is set
GOOGLE_API_KEY = os.environ.get("GEMINI_API_KEY")
if not GOOGLE_API_KEY:
    print("Error: Please set the GEMINI_API_KEY environment variable.")
    exit()

genai.configure(api_key=GOOGLE_API_KEY)

conversation_history = []

# Define a function schema for suggesting tools
tool_suggestion_schema = {
    "name": "suggest_security_tool",
    "description": "Suggests a relevant security tool and its basic usage based on the user's request.",
    "parameters": {
        "type": "object",
        "properties": {
            "tool_name": {
                "type": "string",
                "description": "The name of the security tool."
            },
            "basic_command": {
                "type": "string",
                "description": "A basic command-line example for the tool."
            },
            "reasoning": {
                "type": "string",
                "description": "Why this tool is relevant to the user's request."
            }
        },
        "required": ["tool_name", "basic_command", "reasoning"]
    }
}

def get_bug_bounty_support(user_question, user_role="general security enthusiast", history=None, model_name=DEFAULT_MODEL):
    """
    Sends the user's question to the Gemini Pro model and returns the response.
    """
    prompt = f"""You are an AI assistant for {user_role} in cybersecurity. Please answer the following question directly and concisely: {user_question}"""
    model = genai.GenerativeModel(model_name)
    try:
        response = model.generate_content(prompt)
        if response.parts and hasattr(response.parts[0], "text"):
            return response.parts[0].text
        elif response.candidates and response.candidates[0].content.parts and hasattr(response.candidates[0].content.parts[0], "text"):
            return response.candidates[0].content.parts[0].text
        else:
            return "No specific answer could be generated for this question."
    except Exception as e:
        error_message = f"An error occurred: {e}"
        print(error_message)
        return error_message

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bug Bounty AI Assistant")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL, help="Specify the Gemini model to use")
    args = parser.parse_args()

    print("Welcome to the Bug Bounty AI Assistant!")
    while True:
        question = input("\nAsk your bug bounty or security question (or type 'exit' to quit): ")
        if question.lower() == 'exit':
            break
        if not question.strip():  # Input validation for empty questions
            print("Please enter a question.")
            continue

        # Option to ask for user role
        user_role_input = input("Are you a bug bounty hunter, red teamer, blue teamer, or something else? (leave blank for general): ")
        user_role = user_role_input if user_role_input else "general security enthusiast"

        answer = get_bug_bounty_support(question, user_role=user_role, history=conversation_history, model_name=args.model)
        print("\nAI Assistant's Response:")
        print(answer)
        conversation_history.append({"user": question, "model": answer})