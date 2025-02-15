import json
import logging
from fastapi import FastAPI, File, UploadFile
import pandas as pd
import uvicorn
import os
import shutil
import sqlite3
from fastapi.responses import JSONResponse
from app import DataPreprocessor, EnhancedCyberSecuritySystem

app = FastAPI()

# Make sure there is a folder to save the uploaded files
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Create a SQLite database to store historical records
DB_PATH = "cybersecurity_logs.db"
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS threat_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        total_samples INTEGER,
        potential_threats INTEGER,
        high_risk_threats INTEGER,
        average_threat_score REAL
    )
''')
conn.commit()
conn.close()

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    try:
        file_location = os.path.join(UPLOAD_DIR, file.filename)

        # Temporarily open the file, write it, then close it to ensure it is not reserved
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Data processing
        preprocessor = DataPreprocessor()
        X, y = preprocessor.load_and_preprocess(file_location)

        if X is None or y is None:
            return {"error": "❌ Failed to process the file. Make sure the data is correct."}

        # Run an attack detection model
        system = EnhancedCyberSecuritySystem()
        num_classes = len(set(y))
        system.initialize_models(num_classes, X.shape[1])

        # Use the same data for training and testing in this case
        results, threat_report = system.train_and_evaluate(X, X, y, y)

        if threat_report is None:
            return {"error": "❌ فشل في إنشاء تقرير التهديدات."}

        # Store the results in the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO threat_logs (timestamp, total_samples, potential_threats, high_risk_threats, average_threat_score)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            threat_report.get("timestamp"),
            threat_report.get("total_samples", 0),
            threat_report.get("potential_threats", 0),
            threat_report.get("high_risk_threats", 0),
            threat_report.get("average_threat_score", 0.0)
        ))
        conn.commit()
        conn.close()

        # Make sure to close the file before deleting it
        try:
            os.remove(file_location)
            logging.info(f"🗑️ The temporary file has been deleted: {file_location}")
        except Exception as e:
            logging.warning(f"⚠️ The temporary file was not deleted: {str(e)}")

        return threat_report

    except Exception as e:
        logging.error(f"❌ Error parsing file: {str(e)}")
        return {"error": f"❌ An error occurred: {str(e)}"}

@app.post("/retrain")
async def retrain(data: dict):
    try:
        logging.info("🔄 Start retraining the model based on the detected threats...")
        preprocessor = DataPreprocessor()
        system = EnhancedCyberSecuritySystem()

        if "threat_details" in data and data["threat_details"]:
            X_new = [item["pattern"] for item in data["threat_details"] if "pattern" in item]
            if X_new:
                X_new = pd.DataFrame(X_new)
                system.initialize_models(len(set(data.get("potential_threats", []))), X_new.shape[1])
                system.train_and_evaluate(X_new, X_new, data.get("potential_threats", []),
                                          data.get("potential_threats", []))
                logging.info("✅The model has been successfully retrained!")
                return JSONResponse(content=json.loads(
                    json.dumps({"message": "✅ The model is updated based on detected threats."}, ensure_ascii=False)),
                                    media_type="application/json; charset=utf-8")

        return JSONResponse(content=json.loads(
            json.dumps({"message": "⚠️Not enough data was found for retraining."}, ensure_ascii=False)),
                            media_type="application/json; charset=utf-8")

    except Exception as e:
        logging.error(f"❌ Error during retraining: {str(e)}")
        return JSONResponse(
            content=json.loads(json.dumps({"error": f"❌ An error occurred during retraining: {str(e)}"}, ensure_ascii=False)),
            media_type="application/json; charset=utf-8")

@app.get("/logs")
def get_logs():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM threat_logs ORDER BY timestamp DESC")
        logs = cursor.fetchall()
        conn.close()
        return {"logs": logs}
    except Exception as e:
        logging.error(f"❌ Error while fetching records: {str(e)}")
        return {"error": f"❌ An error occurred while fetching records: {str(e)}"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
