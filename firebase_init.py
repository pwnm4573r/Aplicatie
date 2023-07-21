import firebase_admin
from firebase_admin import credentials

cred = credentials.Certificate("C:/Users/priho/Downloads/PCEP/app/joc4punct0-firebase-adminsdk-xfbgc-8508e04e2f.json")
firebase_admin.initialize_app(cred)