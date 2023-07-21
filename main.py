import firebase_init
from kivy.app import App

from kivy.uix.screenmanager import ScreenManager
from screens import RegistrationScreen, HomeScreen, FriendListScreen, ChatsScreen  # imports the screen classes from screens.py

class MyApp(App):
    def build(self):
        sm = ScreenManager()
        sm.add_widget(RegistrationScreen(name='register'))  # Adds the registration screen to the ScreenManager
        sm.add_widget(HomeScreen(name='home'))  # Adds the home screen to the ScreenManager
        sm.add_widget(FriendListScreen(name='friend_list'))  # Use 'friend_list' as the name
        sm.add_widget(ChatsScreen(name='chats'))
        return sm  # The build method must return a widget, in this case it's the ScreenManager

if __name__ == '__main__':
    MyApp().run()  # This starts the app