import streamlit as st
import pandas as pd
import glob
import os
import time

st.set_page_config(page_title="CrewAI Scanner Dashboard", layout="centered")

st.title("🚀 CrewAI Vulnerability Scanner Dashboard")

def get_latest_summary():
    files = glob.glob("reports/scan_summary_*.xlsx")
    if not files:
        return None
    files.sort(key=os.path.getmtime, reverse=True)
    return files[0]

placeholder = st.empty()

while True:
    latest_file = get_latest_summary()
    with placeholder.container():
        if latest_file:
            df = pd.read_excel(latest_file)
            st.success(f"Số IP đã quét thành công: {len(df)}")
            st.dataframe(df)
        else:
            st.warning("Chưa có dữ liệu quét.")
    time.sleep(5)
    placeholder.empty()
