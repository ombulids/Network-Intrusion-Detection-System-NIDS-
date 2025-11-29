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
       attacktype = st.radio("Attack type",["Neptune","Satan"])
    with col2:
        OS = st.radio("Operating System",["Windows","Linux","Android","Mac"])
    AttackC = st.number_input("Attack Count",min_value=1000,max_value=3000)
    button = st.button("Sumit")
    if button == True:
        st.write("Analyzing....")
        if attacktype == "Neptune":
                st.success("Analyzing complete")
                st.warning(f"🚨 WARNING: High Traffic Attack")
                if OS == "Windows":
                    st.write("Your **Windows** system's connection points are clogged, like a traffic jam. Services are timing out.")
                elif OS == "Linux" or OS == "Mac":
                   st.write(f"Your {OS} kernel is struggling to process the massive flood of fake connection requests. Expect process failures.")
                elif OS == "Android":
                    st.write(f"Your Android device feels frozen and is rapidly draining battery due to network overload.")
                    
        elif attacktype == "Satan":
                st.success("Analyzing complete")
                st.warning(f" WARNING: System Scouting Attack")
                if OS == "Windows":
                    st.write(f"An attacker is aggressively knocking on every virtual door on your **Windows** machine, looking for an open security flaw.")
                elif OS == "Linux" or OS == "Mac":
                    st.write(f"Automated tools are bombarding your {OS} ports to map vulnerabilities. Your security logs are filling up quickly.")
                elif OS == "Android":
                    st.write(f"A high-volume port scan is hitting your Android device, searching for any way to compromise its privacy settings.")
        if 1000 < AttackC <= 1500:
                severity = "Low"
                status = "The system is starting to feel slightly slow."
        elif 1500 < AttackC <= 2000:
                st.write("Medium")
                st.write("Internet activity is noticeably delayed, and some applications may stop responding.")
        elif 2000 < AttackC <= 2500:
                st.write("High")
                st.write("Core functions are failing. You might lose connection completely.")
        elif 2500 < AttackC < 3000:
                st.write("Critical")
                st.write("The entire system has crashed or is completely frozen.")
        else:
            print( "No immediate threat detected in this range.")