import streamlit as st
import pandas as pd
import requests
import os
from requests.exceptions import ConnectionError
import time
import json

# Address and interface setting
st.set_page_config(page_title="Cyber ​​attack detection system", layout="wide")
st.title("🔍 Cyber ​​attack detection system")

# Check server status
def check_server():
    try:
        requests.get("http://127.0.0.1:8000/")
        return True
    except:
        return False

# Display a warning if the server is offline
if not check_server():
    st.error("""
    ⚠️ Analysis server not found. Please follow these steps:
    1. Open a new terminal
    2. Go to the project folder
    3. Run the server with the command:
       ```
       python api.py
       ```
    4. Wait for the server to start and then reload this page
    """)
    st.stop()

# Download the file from the user
uploaded_file = st.file_uploader("📂 Upload a CSV file for analysis", type=["csv"])

if uploaded_file is not None:
    try:
        # Create a Downloads folder if it does not exist
        os.makedirs("uploads", exist_ok=True)

        # Temporarily save the uploaded file
        file_path = os.path.join("uploads", uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        st.success(f"✅ The file has been uploaded successfully: {uploaded_file.name}")

        # Ensure that the analysis is performed only once
        if "threat_report" not in st.session_state:
            with st.spinner("🔄 Analyzing data... Please wait..."):
                try:
                    with open(file_path, "rb") as file:
                        response = requests.post("http://127.0.0.1:8000/analyze", files={"file": file}, timeout=600)

                    if response.status_code == 200:
                        st.session_state["threat_report"] = response.json()

                        # Retrain the model when new threats are detected
                        if st.session_state["threat_report"].get('potential_threats', 0) > 0:
                            retrain_response = requests.post("http://127.0.0.1:8000/retrain", json={"data": st.session_state["threat_report"]})
                            if retrain_response.status_code == 200:
                                st.success("✅ The model is updated based on detected threats!")
                            else:
                                st.warning("⚠️ The system was unable to retrain successfully.")
                    else:
                        st.error(f"❌ Server error: {response.status_code}")
                except ConnectionError:
                    st.error("""
                    ❌ Failed to connect to the server. Make sure:
                    1. Run a server FastAPI (api.py)
                    2.That port 8000 is available
                    3. There is no firewall blocking the connection
                    """)
                except Exception as e:
                    st.error(f"❌ An unexpected error occurred: {str(e)}")
                finally:
                    try:
                        if os.path.exists(file_path):
                            os.remove(file_path)
                    except Exception as e:
                        st.warning(f"⚠️ Warning: The temporary file has not been deleted: {str(e)}")

        if "threat_report" in st.session_state:
            threat_report = st.session_state["threat_report"]

            st.subheader("📊 Report detected threats")
            col1, col2 = st.columns(2)

            with col1:
                st.metric("📌 Number of samples", threat_report.get('total_samples', 0))
                st.metric("⚠️ Potential threats", threat_report.get('potential_threats', 0))

            with col2:
                st.metric("🔥High-risk threats", threat_report.get('high_risk_threats', 0))
                st.metric("📊 Average threat score", f"{threat_report.get('average_threat_score', 0):.2f}%")

            # View details in a table
            if threat_report.get('threat_details'):
                st.subheader("Details of threats")
                df = pd.DataFrame(threat_report['threat_details'])
                st.dataframe(df)
            else:
                st.success("✅ No threats detected!")

            # Download report button without reloading the data
            json_report = json.dumps(threat_report, indent=2, ensure_ascii=False)
            st.download_button(
                "📥 Download the report in JSON",
                data=json_report,
                file_name="threat_report.json",
                mime="application/json"
            )
    except Exception as e:
        st.error(f"❌ An error occurred while processing the file: {str(e)}")

st.subheader("📜 Previous records")

if st.button("📂 View saved records"):
    response = requests.get("http://127.0.0.1:8000/logs")

    if response.status_code == 200:
        logs = response.json().get("logs", [])
        if logs:
            df_logs = pd.DataFrame(logs, columns=["ID", "Timing", "Number of samples", "Potential threats",
                                                  "High-risk threats  ", "Average threat score  "])
            st.dataframe(df_logs)
        else:
            st.info("ℹ️ There are no records saved.")
    else:
        st.error("❌ Failed to fetch records.")
