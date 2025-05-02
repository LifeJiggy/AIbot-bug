import google.generativeai as genai
import os

# Replace with your actual Gemini API key
GOOGLE_API_KEY = os.environ.get("GEMINI_API_KEY")
if not GOOGLE_API_KEY:
    print("Error: Please set the GEMINI_API_KEY environment variable.")
    exit()

genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel('gemini-2.5-pro-exp-03-25')

def get_bug_bounty_support(user_question):
    """
    Sends the user's question to the Gemini Pro model and returns the response.

    Args:
        user_question: The question asked by the user.

    Returns:
        str: The AI's response to the question.
    """
    try:
        response = model.generate_content(user_question)
        return response.text
    except Exception as e:
        return f"An error occurred: {e}"

if __name__ == "__main__":
    print("Welcome to the Bug Bounty AI Assistant!")
    while True:
        question = input("\nAsk your bug bounty or security question (or type 'exit' to quit): ")
        if question.lower() == 'exit':
            break
        if question:
            answer = get_bug_bounty_support(question)
            print("\nAI Assistant's Response:")
            print(answer)
        else:
            print("Please enter a question.")