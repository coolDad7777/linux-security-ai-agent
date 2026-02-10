class ConversationManager:
    def __init__(self):
        self.history = []  # List to store conversation history
        self.context = {}  # Dictionary to manage context

    def add_message(self, message):
        self.history.append(message)  # Add a new message to the history

    def set_context(self, key, value):
        self.context[key] = value  # Set a context value

    def get_context(self):
        return self.context  # Get the current context

    def clear_history(self):
        self.history = []  # Clear the conversation history

    def get_history(self):
        return self.history  # Get the conversation history

# Usage example:
# cm = ConversationManager()
# cm.add_message("Hello!")
# cm.set_context("user_name", "Alice")
# print(cm.get_history())
# print(cm.get_context())