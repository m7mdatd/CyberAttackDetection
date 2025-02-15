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

# التأكد من وجود مجلد لحفظ الملفات المرفوعة
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# إنشاء قاعدة بيانات SQLite لتخزين السجلات السابقة
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

        # فتح الملف مؤقتًا وكتابته، ثم إغلاقه لضمان عدم حجزه
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # معالجة البيانات
        preprocessor = DataPreprocessor()
        X, y = preprocessor.load_and_preprocess(file_location)

        if X is None or y is None:
            return {"error": "❌ فشل في معالجة الملف. تأكد من صحة البيانات."}

        # تشغيل نموذج الكشف عن الهجمات
        system = EnhancedCyberSecuritySystem()
        num_classes = len(set(y))
        system.initialize_models(num_classes, X.shape[1])

        # استخدام نفس البيانات للتدريب والاختبار في هذه الحالة
        results, threat_report = system.train_and_evaluate(X, X, y, y)

        if threat_report is None:
            return {"error": "❌ فشل في إنشاء تقرير التهديدات."}

        # تخزين النتائج في قاعدة البيانات
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

        # التأكد من إغلاق الملف قبل حذفه
        try:
            os.remove(file_location)
            logging.info(f"🗑️ تم حذف الملف المؤقت: {file_location}")
        except Exception as e:
            logging.warning(f"⚠️ لم يتم حذف الملف المؤقت: {str(e)}")

        return threat_report

    except Exception as e:
        logging.error(f"❌ خطأ في تحليل الملف: {str(e)}")
        return {"error": f"❌ حدث خطأ: {str(e)}"}

@app.post("/retrain")
async def retrain(data: dict):
    try:
        logging.info("🔄 بدء إعادة تدريب النموذج بناءً على التهديدات المكتشفة...")
        preprocessor = DataPreprocessor()
        system = EnhancedCyberSecuritySystem()

        if "threat_details" in data and data["threat_details"]:
            X_new = [item["pattern"] for item in data["threat_details"] if "pattern" in item]
            if X_new:
                X_new = pd.DataFrame(X_new)
                system.initialize_models(len(set(data.get("potential_threats", []))), X_new.shape[1])
                system.train_and_evaluate(X_new, X_new, data.get("potential_threats", []),
                                          data.get("potential_threats", []))
                logging.info("✅ تم إعادة تدريب النموذج بنجاح!")
                return JSONResponse(content=json.loads(
                    json.dumps({"message": "✅ تم تحديث النموذج بناءً على التهديدات المكتشفة."}, ensure_ascii=False)),
                                    media_type="application/json; charset=utf-8")

        return JSONResponse(content=json.loads(
            json.dumps({"message": "⚠️ لم يتم العثور على بيانات كافية لإعادة التدريب."}, ensure_ascii=False)),
                            media_type="application/json; charset=utf-8")

    except Exception as e:
        logging.error(f"❌ خطأ أثناء إعادة التدريب: {str(e)}")
        return JSONResponse(
            content=json.loads(json.dumps({"error": f"❌ حدث خطأ أثناء إعادة التدريب: {str(e)}"}, ensure_ascii=False)),
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
        logging.error(f"❌ خطأ أثناء جلب السجلات: {str(e)}")
        return {"error": f"❌ حدث خطأ أثناء جلب السجلات: {str(e)}"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
