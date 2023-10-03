import os
import json
from kivy.clock import Clock
import db
from kivy.app import App
from screens import MyScreenManager  # import MyScreenManager

class MyApp(App):
    current_user = None

    def build(self):
        self.screen_manager = MyScreenManager()
        return self.screen_manager

    def on_start(self):
        if not self.private_key_exists():
            # If the private key doesn't exist, take the user to the registration/login screen.
            self.screen_manager.current = 'register'  # If private_key.pem does not exist, this takes the user to the regitration screen. 
        else:
            self.screen_manager.current = 'password' # If there is a private_key.pem file, the user is taken to the password screen.

        if not os.path.isfile('user.json'):
            with open('user.json', 'w') as f:
                json.dump({}, f)

        if not os.path.isfile('chat.json'):
            with open('chat.json', 'w') as f:
                json.dump({}, f)
        chats_screen = self.screen_manager.get_screen('chats')
        Clock.schedule_interval(chats_screen.fetch_latest_messages, 10)

    def private_key_exists(self):
        return os.path.exists('private_key.pem')

    def on_stop(self):
        # Delete the chat.json file
        if os.path.isfile('chat.json'):
            os.remove('chat.json')

if __name__ == '__main__':
    #firebase_admin.initialize_app()
    MyApp().run()  # This starts the app