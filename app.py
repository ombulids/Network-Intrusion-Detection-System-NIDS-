import streamlit as st
import pandas as pd
import joblib as jb
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]
# Loading Data And Model in the App
data_system = jb.load("Model_Nids.pkl")
model = data_system['model']
encoders = data_system['encoders']
# 1st interfance of the app
st.header("Network Intrusion Detection system")
st.sidebar.header('Home')
home = st.sidebar.radio("Chose The Model",["Intruder Detector","Attacker Check(Opearthing System)"])


#For Intruder Detector
if home =="Intruder Detector":
    st.title("Upload Network Log files")
    Data = st.file_uploader("Upload the data u want to test(.txt , .csv)",accept_multiple_files=True,type=["txt","csv"])
    if Data:
        df_list = [pd.read_csv(file, header=None) for file in Data]
        df = pd.concat(df_list, ignore_index=True)
        df = df.iloc[:, :41]
        df.columns = columns
        st.write("Analyzing....")
        try:
            for col, encoder in encoders.items():
                df[col] = df[col].apply(lambda x: x if x in encoder.classes_ else encoder.classes_[0]) 
                df[col] = encoder.transform(df[col])
            predictions = model.predict(df)
            df['Prediction'] = ["Attack" if x == 1 else "Normal" for x in predictions]
            st.success("Analysis Complete!")
            # Visualization
            st.subheader("Traffic Distribution")
            st.write(df['Prediction'].value_counts())
            # Detailed View
            st.subheader("Detailed Logs with Predictions")
            # Highlight attacks in red
            def highlight_attack(s):
                return ['background-color:#FF0000 ' if v == 'Attack' else '' for v in s]
            if df.size > 200000:
                st.warning(f"Dataset is large ({len(df)} rows). Displaying the top 20 ")
                st.dataframe(df.head(20).style.apply(highlight_attack, subset=['Prediction']))
            else:
                st.dataframe(df.style.apply(highlight_attack, subset=['Prediction']))
        except Exception as e:
            st.error(f"Error during processing: {e}")


# For Attack Checker
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
    

