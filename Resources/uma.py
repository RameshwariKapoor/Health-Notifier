import streamlit as st
from cryptography.fernet import Fernet
import sqlite3
import numpy as np
import pickle
from keras.models import load_model
import multiple_disease_pred
import sklearn

# Load the entire model
# Load the entire model
loaded_model1 = pickle.load(open("diabetes_model.h5", "rb"))
loaded_model2 = pickle.load(open("heart_disease_model.h5", "rb"))
loaded_model3 = pickle.load(open("parkinsons_model.h5", "rb"))


# Function to create or connect to the database
def create_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Function to insert user data into the database
def insert_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()
    conn.close()

# Function to retrieve user data from the database
def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user

# Function to encrypt a string
def encrypt_text(text):
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(text.encode())
    return cipher_text, key

# Function to decrypt a string
def decrypt_text(cipher_text, key):
    cipher_suite = Fernet(key)
    plain_text = cipher_suite.decrypt(cipher_text).decode()
    return plain_text

# Main function to run the Streamlit app
def main():
    create_db()

    st.title("Health Prediction App")

    menu = ["Login", "Register"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Login":
        st.subheader("Login Section")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login"):
                user = get_user(username)
                if user and user[2] == password:
                    st.success("Login Successful")
                    st.experimental_set_query_params(user_id=user[0])
                else:
                    st.error("Invalid Credentials")
    elif choice == "Register":
        st.subheader("Register Section")
        new_username = st.text_input("Username")
        new_password = st.text_input("Password", type="password")
        if st.button("Register"):
            insert_user(new_username, new_password)
            st.success("Registration Successful")

    user_id = st.experimental_get_query_params().get("user_id", [None])[0]

    if user_id is not None:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        user_name = cursor.fetchone()[0]
        conn.close()
        multiple_disease_pred.app()
        

if __name__ == '__main__':
    main()