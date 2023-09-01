import requests
import json
import os
from kivy.clock import Clock
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
from cryptography.hazmat.primitives import serialization, asymmetric
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
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

        # Sign Out Button
        signout_button = Button(text='Sign Out', size_hint=(1, 0.3))
        signout_button.bind(on_press=self.sign_out)
        layout.add_widget(signout_button)

        self.add_widget(layout)

    def go_to_friend_list(self, instance):
        self.manager.current = 'friend_list'

    def go_to_chats(self, instance):
        self.manager.current = 'chats'
        chatroom_screen = self.manager.get_screen('chats')
        chatroom_screen.load_firestore_chats()
        chatroom_screen.update_chat_list()

    def sign_out(self, instance):
        def confirmed(instance):
            """Action to perform after the user confirms signing out."""
            App.get_running_app().current_user = None
            # Delete private key
            if os.path.isfile('private_key.pem'):
                os.remove('private_key.pem')
            if os.path.isfile('user.json'):
                os.remove('user.json')
            # Transition to the Registration screen
            self.manager.current = 'register'
            popup.dismiss()  # Close the popup

        def cancel(instance):
            """Action to perform if the user cancels signing out."""
            popup.dismiss()  # Close the popup

        content = BoxLayout(orientation='vertical', spacing=10, padding=10)
        message = Label(
            text="!!!Warning!!!\nSigning out will delete your private key. \n*ANY MESSAGES RECEIVED WHILE SIGNED OUT WILL BE INACCESSIBLE!*\n Are you sure you want to sign out?",
            size_hint_y=None,
            valign='top',
            halign='center',
            font_size='16sp',  # Reduce font size to fit the text
            color = (1, 0, 0, 1)
        )
        message.bind(texture_size=message.setter('size'))
        yes_button = Button(text="Yes", on_press=confirmed)
        no_button = Button(text="No", on_press=cancel)

        content.add_widget(message)
        content.add_widget(yes_button)
        content.add_widget(no_button)

        popup = Popup(title='Confirm Sign Out', content=content, size_hint=(0.9, 0.5))
        popup.open()

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
                self.write_username_to_file(username)
                self.manager.current = 'home'  # Transition to the Home screen
                App.get_running_app().current_user = username
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
                            # 1. Generate a new key pair
                        key = rsa.generate_private_key(
                            public_exponent=65537,
                            key_size=2048,
                        )

                            # 2. Store private key locally
                        private_key_pem = key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        ) 
                        with open('private_key.pem', 'wb') as f:
                            f.write(private_key_pem)

                            # 3. Update the public key in Firestore
                        public_key_pem = key.public_key().public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                        user_ref.update({'public_key': public_key_pem.decode()})

                        App.get_running_app().current_user = username
                        self.message.text = 'Login successful.'
                        self.write_username_to_file(username)
                        self.manager.current = 'home'  # Transition to the Home screen
                    else:
                        self.message.text = 'Invalid password.'
                else:
                    self.message.text = 'User does not exist.'
            except Exception as e:
                self.message.text = str(e)
        else:
            self.message.text = 'Please enter a username and password.'

    def write_username_to_file(self, username):
        with open('user.json', 'w') as f:
            json.dump({"username": username}, f)

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

    def on_enter(self):
        self.load_friends()
    
    def go_to_home(self):
        # Define the behavior of the back button here
        self.manager.current = 'home'

    def load_friends(self):
    # Get the friends from the Firestore database
        db = firestore.client()
        friends_ref = db.collection('friends').document(App.get_running_app().current_user).collection('user_friends')
        friends = friends_ref.stream()

        for friend in friends:
            friend_data = friend.to_dict()
            username = friend_data.get('username')
            public_key = friend_data.get('public_key')

            # Add the friend to the local friend list
            self.friends[username] = public_key

        self.update_friend_list()


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

            # Save the friend to Firestore
            db.collection('friends').document(App.get_running_app().current_user).collection('user_friends').document(username).set({
                'username': username,
                'public_key': public_key
            })

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
            # Delete the friend from Firestore
            db = firestore.client()
            db.collection('friends').document(App.get_running_app().current_user).collection('user_friends').document(username).delete()
            
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

        # If the chat doesn't exist, create a new one
        if username not in chatroom_screen.chats:
            chatroom_screen.chats[username] = Chat(username)
        
        chatroom_screen.update_chat_list()

        chatroom_screen.open_chat(instance, username)


    def send_chat_message(self, username, message):
        # Fetch the chatroom_screen
        chatroom_screen = self.manager.get_screen('chats')
        
        # Get the relevant Chat object from the chats dictionary in ChatsScreen
        chat = chatroom_screen.chats.get(username)

        if chat:
            # Add the new message to the Chat object
            chat.add_message(message)

            # Also update the chat list in the UI
            chatroom_screen.update_chat_list()
            
            # Now update the list of chats in Firestore
            db = firestore.client()
            
            # First, prepare the list of chat usernames
            chat_usernames = list(chatroom_screen.chats.keys())
            
            # Then, store this list in Firestore
            db.collection('chats').document(App.get_running_app().current_user).set({
                'chats': chat_usernames
            })
        else:
            print(f"No chat with {username} found")

class ChatsScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.chats = {}  # Dictionary to store chats (username: Chat)
        self.current_chat_id = None
        self.load_firestore_chats()

        # Main layout
        layout = BoxLayout(orientation='vertical')

        top_row = BoxLayout(orientation='horizontal', size_hint=(1, 0.1))

        # Back Button
        back_button = BackButton(callback=self.go_to_home, text='Back', size_hint=(None, None), size=(100, 50))

        chats_label = Label(text='Chats', size_hint=(0.8, 1))

        # Add back button and chats label to the top row layout
        top_row.add_widget(back_button)
        top_row.add_widget(chats_label)

        # Add the top row layout to the main layout
        layout.add_widget(top_row)

        # Chat List Layout
        self.chat_list_layout = BoxLayout(orientation='vertical', spacing=10, size_hint=(1, None))
        self.chat_list_scrollview = ScrollView(do_scroll_x=False, do_scroll_y=True)
        self.chat_list_scrollview.add_widget(self.chat_list_layout)
        layout.add_widget(self.chat_list_scrollview)

        self.add_widget(layout)

    def load_firestore_chats(self):
        # Fetch the chats from Firestore
        db = firestore.client()
        doc_ref = db.collection('chats').document(App.get_running_app().current_user)
        doc = doc_ref.get()

        if doc.exists:
            # Fetch the list of chat usernames from Firestore
            chat_usernames = doc.to_dict().get('chats', [])
            
            # Update the self.chats dictionary
            for username in chat_usernames:
                self.chats[username] = Chat(username)

    def decrypt_with_private_key(self, ciphertext):
        # Load the private key from the file
        with open('private_key.pem', 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Decrypt the message using the private key
        plaintext = private_key.decrypt(
            ciphertext,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def fetch_latest_messages(self, dt):
        # Fetch only the current user's messages.
        username = App.get_running_app().current_user  # Assuming there's a method/attribute with the current user's username
        
        try:
            url = f'https://server-middleware-r4ajsmn3fa-ez.a.run.app/get_message/{username}'
            response = requests.get(url)
            if response.status_code != 200:
                print(f'Error fetching messages for {username}: {response.status_code}')
                return

            messages = response.json()
            
            # Skip if there are no new messages
            if messages:
                for message_data in messages:
                    try:
                        print(f"Sample message structure for {username}: {message_data}")  # Log the message data
                        
                        # Extracting the sender and encrypted message
                        sender = message_data.get('message', {}).get('sender', 'unknown')
                        encrypted_message_hex = message_data.get('message', {}).get('message', None)

                        if not encrypted_message_hex:
                            print(f"Message data is missing expected keys: {message_data}")
                            continue

                        # Convert the hex string to bytes
                        encrypted_message_bytes = bytes.fromhex(encrypted_message_hex)
                        
                        # Decrypt the message using the private key
                        decrypted_message = self.decrypt_with_private_key(encrypted_message_bytes)

                        # Get the chat object for the sender
                        chat = self.chats.get(sender, None)
                        if not chat:
                            print(f"No chat object found for sender: {sender}. Available chats: {list(self.chats.keys())}")
                            continue  # continue to the next iteration
                        
                        chat.add_message(decrypted_message.decode())

                        # Store the message to chat.json
                        self.store_to_chat_json(sender, decrypted_message.decode())
                        self.delete_message_from_firestore(username, message_data['id'])

                        # Update the UI with the new messages
                        self.update_chat_list()
                        print(decrypted_message.decode())
                    except Exception as inner_e:
                        print(f"Error decrypting message from {sender}: {inner_e}")

        except Exception as e:
            print(f'Error fetching messages for {username}: {e}')


    def store_to_chat_json(self, sender, message):
        with open('chat.json', 'r') as f:
            chats = json.load(f)

        current_user = App.get_running_app().current_user  # The receiver's username

        if sender not in chats:
            chats[sender] = []

        formatted_message = {sender: message}
        chats[sender].append(formatted_message)

        with open('chat.json', 'w') as f:
            json.dump(chats, f)

    def delete_message_from_firestore(self, user_id, message_id):
        db = firestore.client()
        
        # Reference the user's messages collection
        user_messages_ref = db.collection('users').document(user_id).collection('messages')
        
        # Delete the specific message
        user_messages_ref.document(message_id).delete()

    def go_to_home(self):
        # Define the behavior of the back button here
        self.manager.current = 'home'

    def update_chat_list(self):
        # Clear the current chat list view
        self.chat_list_layout.clear_widgets()

        # Rebuild the chat list view using the chats dictionary
        for username, chat in self.chats.items():
            # Create a container for the chat information
            chat_box = BoxLayout(orientation='horizontal', size_hint=(1, None), height=30)

            # Add a label for the chat's username
            chat_label = Label(text=username, size_hint=(0.6, None), height=30)
            chat_box.add_widget(chat_label)

            # Add a button to delete the chat
            delete_button = Button(text='Delete', size_hint=(0.2, None), height=30)
            delete_button.bind(on_press=partial(self.show_delete_confirmation, username=username))
            chat_box.add_widget(delete_button)

            # Add a button to open the chat
            open_button = Button(text='Open', size_hint=(0.2, None), height=30)
            open_button.bind(on_press=partial(self.open_chat, chat_username=username))
            chat_box.add_widget(open_button)

            # Add the chat container to the chat list layout
            self.chat_list_layout.add_widget(chat_box)

    def show_delete_confirmation(self, instance, username):
        # Prepare the popup
        content = BoxLayout(orientation='vertical', spacing=10)
        message_label = Label(text=f"Are you sure you want to delete chat with {username}?")
        yes_button = Button(text='Yes')
        yes_button.bind(on_press=lambda _, u=username: self.delete_chat(_, u))
        no_button = Button(text='No')
        no_button.bind(on_press=lambda _: self.dismiss_confirmation_popup())
        content.add_widget(message_label)
        content.add_widget(yes_button)
        content.add_widget(no_button)

        self.confirm_popup = Popup(title='Confirmation', content=content, size_hint=(0.6, 0.4), auto_dismiss=False)
        self.confirm_popup.open()

    def delete_chat(self, instance, username):
        if username in self.chats:
            del self.chats[username]
            self.update_chat_list()
            self.delete_firestore_chat(username)  
            print(f"Chat with {username} has been deleted.")
        else:
            print(f"Chat with {username} does not exist.")   
        self.dismiss_confirmation_popup()

    def delete_firestore_chat(self, username):
        db = firestore.client()
        chats_ref = db.collection('chats')
        chats_ref.document(username).delete() 

    def dismiss_confirmation_popup(self):
        if self.confirm_popup is not None:  # Check if there is an active confirmation popup
            self.confirm_popup.dismiss()  # Dismiss the currently active confirmation popup
            self.confirm_popup = None  # Reset the confirm_popup attribute

    def on_leave(self, instance=None):
        if not hasattr(self, 'chat_label'):
            # If chat_label doesn't exist, don't try to save anything
            return
        # Prepare the chat list
        chat_list = []

        # Split the chat label's text into lines
        lines = self.chat_label.label.text.split('\n')

        for line in lines:
            # Split the line into username and message at the first occurrence of ":"
            parts = line.split(':', 1)
            if len(parts) == 2:
                username, message = parts
                # Add the message as a dictionary to the chat list
                chat_list.append({username.strip(): message.strip()})

        # Load all chats
        with open('chat.json', 'r') as f:
            chats = json.load(f)
        # Update the chat
        chats[self.current_chat_id] = chat_list
        # Write the chats back to the file
        with open('chat.json', 'w') as f:
            json.dump(chats, f)
        
        #store info in firestore on chat exit
        db = firestore.client()
        chat_usernames = list(self.chats.keys())
        db.collection('chats').document(App.get_running_app().current_user).set({
            'chats': chat_usernames
        })


    def open_chat(self, instance, chat_username):
        # Open the chat in a popup
        content = BoxLayout(orientation='vertical', spacing=10)

        # Text output for the chat messages (Scrollable Label)
        self.chat_label = ScrollableLabel(size_hint=(1, 0.7))
        content.add_widget(self.chat_label)

        # Text input for the chat messages
        self.chat_input = TextInput(hint_text='Type your message here...', multiline=False, size_hint=(1, 0.1))
        content.add_widget(self.chat_input)

        # Send button to send the chat message
        send_button = Button(text='Send', size_hint=(1, 0.1))
        send_button.bind(on_press=lambda _: self.send_chat_message(chat_username, self.chat_input.text))
        content.add_widget(send_button)

        # Load previous chat messages if they exist
        self.current_chat_id = f"{chat_username}"
        with open('chat.json', 'r') as f:
            chats = json.load(f)
        if self.current_chat_id in chats:
            for message_dict in chats[self.current_chat_id]:
                for username, message in message_dict.items():
                    self.chat_label.update_text(self.chat_label.label.text + f"{username}: {message}\n")

        # Create the chat popup
        chat_popup = Popup(title=f'Chat with {chat_username}', content=content, size_hint=(0.8, 0.6))
        chat_popup.bind(on_dismiss=self.on_leave)
        chat_popup.open()

    def encrypt_message(self, message, public_key):
        # Load public key
        pem = public_key.encode('ascii')
        public_key = serialization.load_pem_public_key(pem)

        # Encrypt the message
        encrypted = public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted

    def get_public_key(self, username):
        db = firestore.client()
        doc_ref = db.collection('users').document(username)
        doc = doc_ref.get()

        if doc.exists:
            return doc.to_dict().get('public_key')
        else:
            print(f'No public key found for user: {username}')
            return None

    def send_chat_message(self, username, message):
        # Fetch the relevant Chat object from the chats dictionary
        chat = self.chats.get(username)

        if chat:
            public_key = self.get_public_key(username)
            if public_key:
                encrypted_message = self.encrypt_message(message, public_key)
                # Add the new encrypted message to the Chat object
                chat.add_message(encrypted_message)

                # Display the unencrypted message in the output chat box
                self.chat_label.update_text(self.chat_label.label.text + f"{App.get_running_app().current_user}: {message}\n")

                # Also update the chat list in the UI
                self.update_chat_list()

                # Send the encrypted message to the middleware server
                self.send_http_request(username, encrypted_message)
                
                # Clear the input box
                self.chat_input.text = ''

                # You could add here the code to update the list of chats in Firestore, 
                # or handle other events when a new message is sent
            else:
                print(f"Can't send message, no public key for {username}")
        else:
            print(f"No chat with {username} found")

    def send_http_request(self, username, encrypted_message):
        # The URL of your middleware server
        url = 'https://server-middleware-r4ajsmn3fa-ez.a.run.app/send_message'

        # Get the current user's username
        sender_username = App.get_running_app().current_user

        # The data to send with the HTTP request
        data = {
            'recipient': username,
            'sender': sender_username,
            'message': encrypted_message.hex()
        }

        # Send the HTTP request
        response = requests.post(url, json=data)

        # Check the HTTP response
        if response.status_code == 200:
            print('Message sent successfully')
        else:
            print('Failed to send message, status code:', response.status_code)

class PasswordScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.layout = BoxLayout(orientation='vertical')

        self.password_input = TextInput(hint_text='Password', multiline=False, password=True)
        self.login_button = Button(text='Log In', on_press=self.verify_password) 
        self.message = Label()  

        self.layout.add_widget(self.password_input)
        self.layout.add_widget(self.login_button)
        self.layout.add_widget(self.message)

        self.add_widget(self.layout)

    def verify_password(self, instance):
        password = self.password_input.text
        if password:
            # Calculate the password hash
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            try:
                # Fetch user data from Firestore based on the username stored in user.json
                with open('user.json', 'r') as f:
                    data = json.load(f)
                    username = data['username']
                
                db = firestore.client()
                user_ref = db.collection('users').document(username)
                user_data = user_ref.get()

                if user_data.exists:
                    data = user_data.to_dict()
                    if data['password_hash'] == password_hash:
                        App.get_running_app().current_user = username
                        self.message.text = 'Login successful.'
                        self.manager.current = 'home'
                    else:
                        self.message.text = 'Invalid password.'
                else:
                    self.message.text = 'User does not exist.'
            except Exception as e:
                self.message.text = str(e)
        else:
            self.message.text = 'Please enter your password.'

class ScrollableLabel(ScrollView):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.label = Label(size_hint=(1, None), padding=(0, 50, 0, 0), text_size=(self.width, None))  
        self.add_widget(self.label)

    def on_size(self, *args):
        self.label.text_size = (self.width, None)
        self.label.height = self.label.texture_size[1]

    def update_text(self, new_text):
        self.label.text = new_text

class Chat:
    def __init__(self, username):
        self.username = username
        self.messages = []

    def add_message(self, message):
        self.messages.append(message)


class MyScreenManager(ScreenManager):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.add_widget(RegistrationScreen(name='register'))  # Adds the registration screen to the ScreenManager
        self.add_widget(PasswordScreen(name='password'))
        self.add_widget(HomeScreen(name='home'))  # Adds the home screen to the ScreenManager
        self.add_widget(FriendListScreen(name='friend_list'))  # Use 'friend_list' as the name
        self.add_widget(ChatsScreen(name='chats'))
    



