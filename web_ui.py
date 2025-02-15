import streamlit as st
import pandas as pd
import requests
import os
from requests.exceptions import ConnectionError
import time
import json

# إعداد العنوان والواجهة
st.set_page_config(page_title="نظام كشف الهجمات السيبرانية", layout="wide")
st.title("🔍 نظام كشف الهجمات السيبرانية")

# التحقق من حالة الخادم
def check_server():
    try:
        requests.get("http://127.0.0.1:8000/")
        return True
    except:
        return False

# عرض تحذير إذا كان الخادم غير متصل
if not check_server():
    st.error("""
    ⚠️ لم يتم العثور على خادم التحليل. الرجاء اتباع الخطوات التالية:
    1. افتح terminal جديد
    2. انتقل إلى مجلد المشروع
    3. قم بتشغيل الخادم باستخدام الأمر:
       ```
       python api.py
       ```
    4. انتظر حتى يبدأ الخادم ثم أعد تحميل هذه الصفحة
    """)
    st.stop()

# تحميل الملف من المستخدم
uploaded_file = st.file_uploader("📂 قم برفع ملف CSV لتحليله", type=["csv"])

if uploaded_file is not None:
    try:
        # إنشاء مجلد التحميلات إذا لم يكن موجوداً
        os.makedirs("uploads", exist_ok=True)

        # حفظ الملف المرفوع مؤقتاً
        file_path = os.path.join("uploads", uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        st.success(f"✅ تم تحميل الملف بنجاح: {uploaded_file.name}")

        # التأكد من أن التحليل يتم مرة واحدة فقط
        if "threat_report" not in st.session_state:
            with st.spinner("🔄 جاري تحليل البيانات... الرجاء الانتظار..."):
                try:
                    with open(file_path, "rb") as file:
                        response = requests.post("http://127.0.0.1:8000/analyze", files={"file": file}, timeout=600)

                    if response.status_code == 200:
                        st.session_state["threat_report"] = response.json()

                        # إعادة تدريب النموذج عند اكتشاف تهديدات جديدة
                        if st.session_state["threat_report"].get('potential_threats', 0) > 0:
                            retrain_response = requests.post("http://127.0.0.1:8000/retrain", json={"data": st.session_state["threat_report"]})
                            if retrain_response.status_code == 200:
                                st.success("✅ تم تحديث النموذج بناءً على التهديدات المكتشفة!")
                            else:
                                st.warning("⚠️ لم يتمكن النظام من إعادة التدريب بنجاح.")
                    else:
                        st.error(f"❌ خطأ في الخادم: {response.status_code}")
                except ConnectionError:
                    st.error("""
                    ❌ فشل الاتصال بالخادم. تأكد من:
                    1. تشغيل خادم FastAPI (api.py)
                    2. أن المنفذ 8000 متاح
                    3. عدم وجود جدار حماية يمنع الاتصال
                    """)
                except Exception as e:
                    st.error(f"❌ حدث خطأ غير متوقع: {str(e)}")
                finally:
                    try:
                        if os.path.exists(file_path):
                            os.remove(file_path)
                    except Exception as e:
                        st.warning(f"⚠️ تحذير: لم يتم حذف الملف المؤقت: {str(e)}")

        if "threat_report" in st.session_state:
            threat_report = st.session_state["threat_report"]

            st.subheader("📊 تقرير التهديدات المكتشفة")
            col1, col2 = st.columns(2)

            with col1:
                st.metric("📌 عدد العينات", threat_report.get('total_samples', 0))
                st.metric("⚠️ التهديدات المحتملة", threat_report.get('potential_threats', 0))

            with col2:
                st.metric("🔥 التهديدات عالية الخطورة", threat_report.get('high_risk_threats', 0))
                st.metric("📊 متوسط درجة التهديد", f"{threat_report.get('average_threat_score', 0):.2f}%")

            # عرض التفاصيل في جدول
            if threat_report.get('threat_details'):
                st.subheader("تفاصيل التهديدات")
                df = pd.DataFrame(threat_report['threat_details'])
                st.dataframe(df)
            else:
                st.success("✅ لا توجد تهديدات مكتشفة!")

            # زر تحميل التقرير دون إعادة تحميل البيانات
            json_report = json.dumps(threat_report, indent=2, ensure_ascii=False)
            st.download_button(
                "📥 تحميل التقرير بصيغة JSON",
                data=json_report,
                file_name="threat_report.json",
                mime="application/json"
            )
    except Exception as e:
        st.error(f"❌ حدث خطأ أثناء معالجة الملف: {str(e)}")

st.subheader("📜 السجلات السابقة")

if st.button("📂 عرض السجلات المحفوظة"):
    response = requests.get("http://127.0.0.1:8000/logs")

    if response.status_code == 200:
        logs = response.json().get("logs", [])
        if logs:
            df_logs = pd.DataFrame(logs, columns=["ID", "التوقيت", "عدد العينات", "التهديدات المحتملة",
                                                  "التهديدات عالية الخطورة", "متوسط درجة التهديد"])
            st.dataframe(df_logs)
        else:
            st.info("ℹ️ لا توجد سجلات محفوظة.")
    else:
        st.error("❌ فشل في جلب السجلات.")
