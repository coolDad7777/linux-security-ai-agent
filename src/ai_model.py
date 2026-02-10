import openai

class OpenAIIntegration:
    def __init__(self, api_key):
        openai.api_key = api_key

    def get_response(self, prompt, model="gpt-3.5-turbo"):
        response = openai.ChatCompletion.create(
            model=model,
            messages=[{"role": "user", "content": prompt}]
        )
        return response['choices'][0]['message']['content']

# Example usage:
# ai = OpenAIIntegration(api_key="your_api_key_here")
# print(ai.get_response("Hello, how are you?"))
