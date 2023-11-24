import streamlit as st
from cryptography.fernet import Fernet
import sqlite3
import pickle
# !pip install streamlit

# import streamlit.report_thread

import numpy as np
from keras.models import load_model

class SessionState:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    @staticmethod
    def get(**kwargs):
        if not hasattr(SessionState, "_instance"):
            SessionState._instance = SessionState(**kwargs)
        return SessionState._instance

# Example of usage
session_state = SessionState.get(run_id=0)

# Load the entire model
loaded_model1 = pickle.load(open("diabetes_model.h5", "rb"))
loaded_model2 = pickle.load(open("heart_disease_model.h5", "rb"))
loaded_model3 = pickle.load(open("parkinsons_model.h5", "rb"))





# Function to create or connect to the database
@st.cache_data
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
@st.cache_data
def insert_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()
    conn.close()

# Function to retrieve user data from the database
@st.cache_data
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

import hashlib

def hash_password(password):
    # Hash the password using a secure hash function (e.g., SHA-256)
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

# Main function to run the Streamlit app
def main():
    create_db()

    st.title("Health Prediction App")

    menu = ["Login", "Register"]
    choice = st.sidebar.selectbox("Menu", menu)

    # Create SessionState
    session_state = SessionState.get(run_id=0)

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
            hashed_password = hash_password(new_password)
            insert_user(new_username, hashed_password)
            st.success("Registration Successful")

    user_id = st.experimental_get_query_params().get("user_id", [None])[0]

    if user_id is not None:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        user_name = cursor.fetchone()[0]
        conn.close()

        selected_diseases = st.multiselect(
            "Select diseases you want to check for:",
            ["Diabetes", "Heart Disease", "Parkinson's Disease"]
        )

        # Use SessionState to keep track of button state
        if st.button("Check Health", key=session_state.run_id):
            session_state.run_id += 1  # Increment run_id to trigger button callback

            if not selected_diseases:
                st.warning("Please select at least one disease.")
            else:
                st.write(f"Hello, {user_name}!")

                # for disease in selected_diseases:
                if selected_diseases[0] == "Diabetes":
                    st.title('Diabetes Prediction using ML')

                    # ... (Your existing code for diabetes prediction)
                    col1, col2, col3 = st.columns(3)

                    with col1:
                        Pregnancies = st.text_input('Number of Pregnancies')

                    with col2:
                        Glucose = st.text_input('Glucose Level')

                    with col3:
                        BloodPressure = st.text_input('Blood Pressure value')

                    with col1:
                        SkinThickness = st.text_input('Skin Thickness value')

                    with col2:
                        Insulin = st.text_input('Insulin Level')

                    with col3:
                        BMI = st.text_input('BMI value')

                    with col1:
                        DiabetesPedigreeFunction = st.text_input('Diabetes Pedigree Function value')

                    with col2:
                        Age = st.text_input('Age of the Person')

                    # code for Prediction
                    diab_diagnosis = ''

                    # creating a button for Prediction
                    if st.button('Diabetes Test Result'):
                        sample_input_scaled = np.array([[Pregnancies, Glucose, BloodPressure, SkinThickness, Insulin, BMI, DiabetesPedigreeFunction, Age]])
                        sample_input_reshaped = sample_input_scaled.reshape((sample_input_scaled.shape[0], 1, sample_input_scaled.shape[1]))
                        diab_prediction = loaded_model2.predict([[Pregnancies, Glucose, BloodPressure, SkinThickness, Insulin, BMI, DiabetesPedigreeFunction, Age]])

                        if (diab_prediction[0] == 1):
                            diab_diagnosis = 'The person is diabetic'
                        else:
                            diab_diagnosis = 'The person is not diabetic'

                        st.success(diab_diagnosis)
                        st.write("Prediction for Diabetes: [Prediction Result]")

                elif selected_diseases[0] == "Heart Disease":
                    st.title('Heart Disease Prediction using ML')
                    col1, col2, col3 = st.columns(3)

                    with col1:
                        age = st.text_input('Age')

                    with col2:
                        sex = st.text_input('Sex')

                    with col3:
                        cp = st.text_input('Chest Pain types')

                    with col1:
                        trestbps = st.text_input('Resting Blood Pressure')

                    with col2:
                        chol = st.text_input('Serum Cholestoral in mg/dl')

                    with col3:
                        fbs = st.text_input('Fasting Blood Sugar > 120 mg/dl')

                    with col1:
                        restecg = st.text_input('Resting Electrocardiographic results')

                    with col2:
                        thalach = st.text_input('Maximum Heart Rate achieved')

                    with col3:
                        exang = st.text_input('Exercise Induced Angina')

                    with col1:
                        oldpeak = st.text_input('ST depression induced by exercise')

                    with col2:
                        slope = st.text_input('Slope of the peak exercise ST segment')

                    with col3:
                        ca = st.text_input('Major vessels colored by flourosopy')

                    with col1:
                        thal = st.text_input('thal: 0 = normal; 1 = fixed defect; 2 = reversable defect')

                    # code for Prediction
                    heart_diagnosis = ''

                    # creating a button for Prediction
                    if st.button('Heart Disease Test Result'):
                        heart_prediction = loaded_model3.predict([[age, sex, cp, trestbps, chol, fbs, restecg,thalach,exang,oldpeak,slope,ca,thal]])

                        if (heart_prediction[0] == 1):
                            heart_diagnosis = 'The person is having heart disease'
                        else:
                            heart_diagnosis = 'The person does not have any heart disease'

                        st.success(heart_diagnosis)
                        st.write("Prediction for Heart Disease: [Prediction Result]")

                elif selected_diseases[0] == "Parkinson's Disease":

                    st.title("Parkinson's Disease Prediction using ML")

                    col1, col2, col3, col4, col5 = st.columns(5)

                    with col1:
                        fo = st.text_input('MDVP:Fo(Hz)')

                    with col2:
                        fhi = st.text_input('MDVP:Fhi(Hz)')

                    with col3:
                        flo = st.text_input('MDVP:Flo(Hz)')

                    with col4:
                        Jitter_percent = st.text_input('MDVP:Jitter(%)')

                    with col5:
                        Jitter_Abs = st.text_input('MDVP:Jitter(Abs)')

                    with col1:
                        RAP = st.text_input('MDVP:RAP')

                    with col2:
                        PPQ = st.text_input('MDVP:PPQ')

                    with col3:
                        DDP = st.text_input('Jitter:DDP')

                    with col4:
                        Shimmer = st.text_input('MDVP:Shimmer')

                    with col5:
                        Shimmer_dB = st.text_input('MDVP:Shimmer(dB)')

                    with col1:
                        APQ3 = st.text_input('Shimmer:APQ3')

                    with col2:
                        APQ5 = st.text_input('Shimmer:APQ5')

                    with col3:
                        APQ = st.text_input('MDVP:APQ')

                    with col4:
                        DDA = st.text_input('Shimmer:DDA')

                    with col5:
                        NHR = st.text_input('NHR')

                    with col1:
                        HNR = st.text_input('HNR')

                    with col2:
                        RPDE = st.text_input('RPDE')

                    with col3:
                        DFA = st.text_input('DFA')

                    with col4:
                        spread1 = st.text_input('spread1')

                    with col5:
                        spread2 = st.text_input('spread2')

                    with col1:
                        D2 = st.text_input('D2')

                    with col2:
                        PPE = st.text_input('PPE')

                    # code for Prediction
                    parkinsons_diagnosis = ''

                    # creating a button for Prediction
                    if st.button("Parkinson's Test Result"):
                        parkinsons_prediction = loaded_model1.predict(
                            [[fo, fhi, flo, Jitter_percent, Jitter_Abs, RAP, PPQ, DDP, Shimmer, Shimmer_dB, APQ3, APQ5, APQ, DDA, NHR, HNR, RPDE, DFA, spread1, spread2, D2, PPE]])

                        if (parkinsons_prediction[0] == 1):
                            parkinsons_diagnosis = "The person has Parkinson's disease"
                        else:
                            parkinsons_diagnosis = "The person does not have Parkinson's disease"

                        st.success(parkinsons_diagnosis)
                        st.write("Prediction for Parkinson's Disease: [Prediction Result]")
                    else:
                        st.success("Health Check Successful")

if __name__ == '__main__':
    main()