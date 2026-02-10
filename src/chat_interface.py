class ChatInterface:
    def __init__(self):
        self.conversation_history = []

    def add_message(self, message, sender):
        self.conversation_history.append({"sender": sender, "message": message})

    def get_history(self):
        return self.conversation_history

    def get_response(self, user_input):
        # Here you would implement your response logic (for example, using an AI model)
        # For simplicity, let's just echo the user input.
        response = f"You said: {user_input}"
        self.add_message(response, "bot")
        return response

    def interactive_chat(self):
        print("Welcome to the Chat Interface!")
        while True:
            user_input = input("You: ")
            if user_input.lower() in ["exit", "quit"]:
                print("Ending chat...")
                break
            self.add_message(user_input, "user")
            response = self.get_response(user_input)
            print(f"Bot: {response}")

# Example of how to use the chat interface
if __name__ == '__main__':
    chat = ChatInterface()
    chat.interactive_chat()