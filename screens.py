from kivy.uix.screenmanager import Screen
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.actionbar import ActionBar, ActionView, ActionPrevious
import firebase_admin
from firebase_admin import auth, firestore
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from functools import partial
import hashlib

class BackButton(Button):
    def __init__(self, callback, **kwargs):
        super().__init__(**kwargs)
        self.callback = callback

    def on_release(self):
        if self.callback:
            self.callback()

class HomeScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Main layout
        layout = BoxLayout(orientation='vertical')

        # Friend List Button
        friend_list_button = Button(text='Friend List', size_hint=(1, 0.3))
        friend_list_button.bind(on_press=self.go_to_friend_list)
        layout.add_widget(friend_list_button)

        # Chats Button
        messages_button = Button(text='Chats', size_hint=(1, 0.3))
        messages_button.bind(on_press=self.go_to_chats)
        layout.add_widget(messages_button)

        self.add_widget(layout)

    def go_to_friend_list(self, instance):
        self.manager.current = 'friend_list'

    def go_to_chats(self, instance):
        self.manager.current = 'chats'

#this is the main screen
class RegistrationScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.layout = BoxLayout(orientation='vertical')

        self.username_input = TextInput(hint_text='Username', multiline=False)
        self.password_input = TextInput(hint_text='Password', multiline=False, password=True)
        self.signup_button = Button(text='Sign Up', on_press=self.signup)
        self.login_button = Button(text='Log In', on_press=self.go_to_login)  # Add login button
        self.message = Label()  # This label will display error messages

        self.layout.add_widget(self.username_input)
        self.layout.add_widget(self.password_input)
        self.layout.add_widget(self.signup_button)
        self.layout.add_widget(self.login_button)
        self.layout.add_widget(self.message)

        self.add_widget(self.layout)

    def signup(self, instance):
        username = self.username_input.text
        password = self.password_input.text

        if username and password:
            # Calculate the password hash
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            # Generate a new key pair
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Serialize the public key
            public_key_pem = key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Data to be sent to Firestore
            data = {
                'username': username,
                'password_hash': password_hash,
                'public_key': public_key_pem.decode()  # Convert bytes to string
            }

            try:
                # Store user data in Firestore
                db = firestore.client()
                db.collection('users').document(username).set(data)

                # Save private key locally
                private_key_pem = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                with open('private_key.pem', 'wb') as f:
                    f.write(private_key_pem)

                self.message.text = 'User registration successful.'
                self.manager.current = 'home'  # Transition to the Home screen
            except Exception as e:
                self.message.text = str(e)

    def go_to_login(self, instance):
        username = self.username_input.text
        password = self.password_input.text

        if username and password:
            # Calculate the password hash
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            try:
                # Fetch user data from Firestore
                db = firestore.client()
                user_ref = db.collection('users').document(username)
                user_data = user_ref.get()

                if user_data.exists:
                    data = user_data.to_dict()
                    if data['password_hash'] == password_hash:
                        self.message.text = 'Login successful.'
                        self.manager.current = 'home'  # Transition to the Home screen
                    else:
                        self.message.text = 'Invalid password.'
                else:
                    self.message.text = 'User does not exist.'
            except Exception as e:
                self.message.text = str(e)
        else:
            self.message.text = 'Please enter a username and password.'

class FriendListScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.current_popup = None
        self.error_label = None

        self.friends = {}  # Dictionary to store friends (username: public_key)

        # Main layout
        main_layout = BoxLayout(orientation='vertical')

        # Back Button
        back_button = BackButton(callback=self.go_to_home, text='Back', size_hint=(None, None), size=(100, 50))
        main_layout.add_widget(back_button)

        # Friend List Layout
        self.friend_list_layout = BoxLayout(orientation='vertical', spacing=10, size_hint=(1, None))
        self.friend_list_scrollview = ScrollView(do_scroll_x=False, do_scroll_y=True)
        self.friend_list_scrollview.add_widget(self.friend_list_layout)
        main_layout.add_widget(self.friend_list_scrollview)

        # Add Friend Button
        button_layout = BoxLayout(orientation='horizontal')
        add_friend_button = Button(text='Add Friend', size_hint=(1, 0.3))
        add_friend_button.bind(on_press=self.show_add_friend_popup)
        button_layout.add_widget(add_friend_button)
        main_layout.add_widget(button_layout)

        self.add_widget(main_layout)
    
    def go_to_home(self):
        # Define the behavior of the back button here
        self.manager.current = 'home'


    def show_add_friend_popup(self, instance):
        content = BoxLayout(orientation='vertical', spacing=10)
        username_input = TextInput(hint_text='Enter Username', multiline=False)
        content.add_widget(username_input)

        buttons_layout = BoxLayout(orientation='horizontal', spacing=10, size_hint=(1, 0.5))
        ok_button = Button(text='OK')
        ok_button.bind(on_press=lambda _: self.add_friend(username_input.text))
        cancel_button = Button(text='Cancel')
        cancel_button.bind(on_press=lambda _: self.dismiss_popup())
        buttons_layout.add_widget(ok_button)
        buttons_layout.add_widget(cancel_button)
        content.add_widget(buttons_layout)

        self.error_label = Label(text='', color=(1, 0, 0, 1))  # Create the error label
        content.add_widget(self.error_label)  # Add the error label to the content

        self._popup = Popup(title='Add Friend', content=content, size_hint=(0.6, 0.4), auto_dismiss=False)
        self.current_popup = self._popup  # Set the current_popup attribute to the new popup
        self._popup.open()

    def add_friend(self, username):
        # Check if the username already exists in the friend list
        if username in self.friends:
            self.error_label.text = "Friend already exists!"
            return

        # Get the public key from the Firestore database
        db = firestore.client()
        user_ref = db.collection('users').document(username)
        user_data = user_ref.get().to_dict()

        if user_data:
            public_key = user_data.get('public_key')

            # Add the friend to the friend list
            self.friends[username] = public_key

            # Create a container for the friend information
            friend_box = BoxLayout(orientation='horizontal', size_hint=(1, None), height=30)

            # Add a label for the friend's username
            friend_label = Label(text=username, size_hint=(0.6, None), height=30)
            friend_box.add_widget(friend_label)

            # Add a button to delete the friend
            delete_button = Button(text='Delete', size_hint=(0.2, None), height=30)
            delete_button.bind(on_press=partial(self.show_delete_confirmation, username=username))
            friend_box.add_widget(delete_button)

            # Add a button to start a chat with the friend
            chat_button = Button(text='Chat', size_hint=(0.2, None), height=30)
            chat_button.bind(on_press=partial(self.go_to_chatroom, username))
            friend_box.add_widget(chat_button)

            # Add the friend container to the friend list layout
            self.friend_list_layout.add_widget(friend_box)
            self.dismiss_popup()
        else:
            self.error_label.text = "User does not exist!"

        #self.dismiss_popup()  # Dismiss the add friend popup

    def show_delete_confirmation(self, instance, username):
        # Prepare the popup
        content = BoxLayout(orientation='vertical', spacing=10)
        message_label = Label(text=f"Are you sure you want to delete {username}?")
        yes_button = Button(text='Yes')
        yes_button.bind(on_press=lambda _, u=username: self.delete_friend(_, u))
        no_button = Button(text='No')
        no_button.bind(on_press=lambda _: self.dismiss_confirmation_popup())
        content.add_widget(message_label)
        content.add_widget(yes_button)
        content.add_widget(no_button)

        self.confirm_popup = Popup(title='Confirmation', content=content, size_hint=(0.6, 0.4), auto_dismiss=False)
        self.confirm_popup.open()

    def update_friend_list(self):
        self.friend_list_layout.clear_widgets()  # Clear the friend list layout

        # Rebuild the friend list layout with the updated friend list
        for username, public_key in self.friends.items():
            friend_box = BoxLayout(orientation='horizontal', size_hint=(1, None), height=30)

            friend_label = Label(text=username, size_hint=(0.6, None), height=30)
            friend_box.add_widget(friend_label)

            delete_button = Button(text='Delete', size_hint=(0.2, None), height=30)
            delete_button.bind(on_press=partial(self.show_delete_confirmation, username=username))
            friend_box.add_widget(delete_button)

            chat_button = Button(text='Chat', size_hint=(0.2, None), height=30)
            chat_button.bind(on_press=partial(self.go_to_chatroom, username))
            friend_box.add_widget(chat_button)

            self.friend_list_layout.add_widget(friend_box)

    def delete_friend(self, instance, username):
        if username in self.friends:
            del self.friends[username]
            self.update_friend_list()
            print(f"Friend {username} has been deleted.")
        else:
            print(f"Friend {username} does not exist.")   
        self.dismiss_confirmation_popup()

    def dismiss_popup(self):
        if self.current_popup is not None:  # Check if there is an active popup
            self.current_popup.dismiss()  # Dismiss the currently active popup
            self.current_popup = None  # Reset the current_popup attribute

    def dismiss_confirmation_popup(self):
        if self.confirm_popup is not None:  # Check if there is an active confirmation popup
            self.confirm_popup.dismiss()  # Dismiss the currently active confirmation popup
            self.confirm_popup = None  # Reset the confirm_popup attribute

    def go_to_chatroom(self, username, instance):
        # Transition to the chat room screen with the selected friend
        self.manager.current = 'chats'
        chatroom_screen = self.manager.get_screen('chats')
        # Prepare the chat popup
        content = BoxLayout(orientation='vertical', spacing=10)

        # Text input for the chat messages
        chat_input = TextInput(hint_text='Type your message here...', multiline=False)
        content.add_widget(chat_input)

        # Send button to send the chat message
        send_button = Button(text='Send')
        send_button.bind(on_press=lambda _: self.send_chat_message(username, chat_input.text))
        content.add_widget(send_button)

        # Create the chat popup
        chat_popup = Popup(title='Chat with {}'.format(username), content=content, size_hint=(0.8, 0.4))
        chat_popup.open()
        #chatroom_screen.set_friend(username)


class ChatsScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        layout = BoxLayout(orientation='vertical')
        messages_label = Label(text='Messages')
        layout.add_widget(messages_label)

        # Back Button
        back_button = BackButton(callback=self.go_to_home, text='Back', size_hint=(None, None), size=(100, 50))
        layout.add_widget(back_button)

        self.add_widget(layout)

    def go_to_home(self):
        # Define the behavior of the back button here
        self.manager.current = 'home'


class MyScreenManager(ScreenManager):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class MyApp(App):
    def build(self):
        return MyScreenManager()


if __name__ == '__main__':
    firebase_admin.initialize_app()
    MyApp().run()

