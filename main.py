import os
import json
from kivy.clock import Clock
import firebase_init
import firebase_admin
from kivy.app import App
from screens import MyScreenManager  # import MyScreenManager

class MyApp(App):
    current_user = None

    def build(self):
        self.screen_manager = MyScreenManager()
        return self.screen_manager

    def on_start(self):
        if not os.path.isfile('chat.json'):
            with open('chat.json', 'w') as f:
                json.dump({}, f)
        chats_screen = self.screen_manager.get_screen('chats')
        Clock.schedule_interval(chats_screen.fetch_latest_messages, 5)

    def on_stop(self):
        # Delete the chat.json file
        if os.path.isfile('chat.json'):
            os.remove('chat.json')

if __name__ == '__main__':
    #firebase_admin.initialize_app()
    MyApp().run()  # This starts the app