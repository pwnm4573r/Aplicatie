import os
import json
import firebase_init
import firebase_admin
from kivy.app import App
from screens import MyScreenManager  # import MyScreenManager

class MyApp(App):
    current_user = None

    def build(self):
        return MyScreenManager()

    def on_start(self):
        if not os.path.isfile('chat.json'):
            with open('chat.json', 'w') as f:
                json.dump({}, f)

    def on_stop(self):
        # Delete the chat.json file
        if os.path.isfile('chat.json'):
            os.remove('chat.json')

if __name__ == '__main__':
    #firebase_admin.initialize_app()
    MyApp().run()  # This starts the app