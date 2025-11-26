import streamlit as st
import pandas as pd
import joblib as jb
model = jb.load("Model_Nids")
st. header("Network Intrusion Detection system")
st.sidebar.header('Home')
home = st.sidebar.radio("Chose The Model",["Intruder Detector","Attacker Check(Opearthing System)"])
if home =="Intruder Detector":
    st.title("Check File is Data to Attack system")
    Data =st.file_uploader("Upload the data u want to test",accept_multiple_files=True,type="txt")
    if Data:
        df = pd.concat([pd.read_csv(file) for file in Data], ignore_index=True)
        st.write("Analyzing....")
        predictions= model.predict(df)
        df["prediction"]= predictions
        st.subheader("Attack Distribution")
        st.bar_chart(df['Prediction'].value_counts())
        st.subheader("Detailed Logs")
        st.dataframe(df)
elif home =="Attacker Check(Opearthing System)":
    col1 , col2 = st.columns(2)
    with col1:
       attacktype = st.radio("Attack type",["Neptune","satan"])
    with col2:
        OS = st.radio("Operating System",["Windows","Linux","Android","Mac"])
    AttackC = st.number_input("Attack Count",min_value=200,max_value=2000)
    if attacktype == "Neptune" and OS == "Windows" and AttackC <500:
        st.write("")
    elif attacktype == "Neptune" and OS == "Windows" and (AttackC >500 and AttackC<1000):
        st.write("")
    elif attacktype == "Neptune" and OS == "Windows" and AttackC >1000:
        st.write("")
    if attacktype == "Neptune" and OS == "Windows" and AttackC <500:
        st.write("")
    if attacktype == "Neptune" and OS == "Windows" and (AttackC >500 and AttackC<1000):
        st.write("")
    if attacktype == "Neptune" and OS == "Windows" and AttackC >1000:
        st.write("")
    

