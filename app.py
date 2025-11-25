import streamlit as st
import pandas as pd
col1,col2 = st.columns(2)
st. header("Network Intruder Detection system")
uplloadeFile =st.file_uploader("Upload the data u want to test",accept_multiple_files=True,type="csv")