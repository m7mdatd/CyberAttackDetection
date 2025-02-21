import streamlit as st
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler, MinMaxScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, recall_score, confusion_matrix, precision_score, f1_score
from sklearn.neighbors import LocalOutlierFactor
from sklearn.cluster import DBSCAN
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense, Conv1D, MaxPooling1D, Flatten, LSTM, Dropout
from tensorflow.keras.callbacks import EarlyStopping
from scipy import stats  # إضافة استيراد scipy.stats
import time
import joblib
import os
from datetime import datetime
import warnings
import tensorflow as tf
from imblearn.over_sampling import SMOTE  # مكتبة موازنة البيانات
from tensorflow.keras.layers import BatchNormalization



warnings.filterwarnings('ignore')


import tensorflow as tf  # إضافة استيراد TensorFlow

def save_models(models, base_path='trained_models'):
    """حفظ النماذج المدربة في مجلد مع التحقق من نجاح العملية"""
    try:
        # إنشاء مجلد للنماذج إذا لم يكن موجوداً
        if not os.path.exists(base_path):
            os.makedirs(base_path)

        # إنشاء مجلد فرعي باسم التاريخ والوقت
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        model_path = os.path.join(base_path, f'models_{timestamp}')
        os.makedirs(model_path)

        saved_models = []
        failed_models = []

        # حفظ النماذج التقليدية
        try:
            joblib.dump(models.get('svm'), os.path.join(model_path, 'svm_model.joblib'))
            saved_models.append('SVM')
        except Exception as e:
            failed_models.append(('SVM', str(e)))

        try:
            joblib.dump(models.get('dt'), os.path.join(model_path, 'dt_model.joblib'))
            saved_models.append('Decision Trees')
        except Exception as e:
            failed_models.append(('Decision Trees', str(e)))

        # حفظ نماذج التعلم العميق
        if models.get('cnn') and models['cnn'].get('model') is not None:
            try:
                models['cnn']['model'].save(os.path.join(model_path, 'cnn_model.keras'), save_format='keras')
                saved_models.append('CNN')
            except Exception as e:
                failed_models.append(('CNN', str(e)))
        else:
            failed_models.append(('CNN', 'نموذج غير موجود أو لم يتم تدريبه'))

        if models.get('rnn') and models['rnn'].get('model') is not None:
            try:
                models['rnn']['model'].save(os.path.join(model_path, 'rnn_model.keras'), save_format='keras')
                saved_models.append('RNN')
            except Exception as e:
                failed_models.append(('RNN', str(e)))
        else:
            failed_models.append(('RNN', 'نموذج غير موجود أو لم يتم تدريبه'))

        # حفظ معلومات إضافية
        metadata = {
            'timestamp': timestamp,
            'model_path': model_path,
            'saved_models': saved_models,
            'failed_models': failed_models
        }
        joblib.dump(metadata, os.path.join(model_path, 'metadata.joblib'))

        # عرض رسائل النجاح والفشل
        if saved_models:
            st.success(f"تم حفظ النماذج التالية بنجاح: {', '.join(saved_models)}")

        if failed_models:
            error_msg = "فشل حفظ النماذج التالية:\n"
            for model, error in failed_models:
                error_msg += f"- {model}: {error}\n"
            st.error(error_msg)

        # إرجاع مسار المجلد فقط إذا تم حفظ نموذج واحد على الأقل
        return model_path if saved_models else None

    except Exception as e:
        st.error(f"خطأ عام في حفظ النماذج: {str(e)}")
        return None

def load_models(model_path):
    """تحميل النماذج المدربة من مجلد مع التحقق من وجود الملفات"""
    try:
        # التحقق من وجود المجلد
        if not os.path.exists(model_path):
            st.error(f"مسار النماذج غير موجود: {model_path}")
            return None

        # قائمة بأسماء الملفات المتوقعة
        expected_files = {
            'svm_model.joblib': 'نموذج SVM',
            'dt_model.joblib': 'نموذج Decision Trees',
            'cnn_model.keras': 'نموذج CNN',
            'rnn_model.keras': 'نموذج RNN'
        }

        # التحقق من وجود جميع الملفات المطلوبة
        missing_files = []
        for filename in expected_files:
            file_path = os.path.join(model_path, filename)
            if not os.path.exists(file_path):
                missing_files.append(expected_files[filename])

        if missing_files:
            st.error(f"الملفات التالية غير موجودة: {', '.join(missing_files)}")
            return None

        # تحميل النماذج التقليدية
        svm_model = joblib.load(os.path.join(model_path, 'svm_model.joblib'))
        dt_model = joblib.load(os.path.join(model_path, 'dt_model.joblib'))

        # تحميل نماذج التعلم العميق
        try:
            cnn_model = load_model(os.path.join(model_path, 'cnn_model.keras'))
        except Exception as e:
            st.error(f"خطأ في تحميل نموذج CNN: {str(e)}")
            return None

        try:
            rnn_model = load_model(os.path.join(model_path, 'rnn_model.keras'))
        except Exception as e:
            st.error(f"خطأ في تحميل نموذج RNN: {str(e)}")
            return None

        return {
            'svm': svm_model,
            'dt': dt_model,
            'cnn': {'model': cnn_model},
            'rnn': {'model': rnn_model}
        }

    except Exception as e:
        st.error(f"خطأ في تحميل النماذج: {str(e)}")
        return None


def load_and_preprocess_data(file):
    """تحميل ومعالجة البيانات مع تحويل تلقائي للتصنيف الثنائي"""
    try:
        # محاولة قراءة الملف بتنسيقات مختلفة
        try:
            data = pd.read_csv(file, encoding='utf-8')
        except:
            try:
                data = pd.read_csv(file, encoding='latin1')
            except:
                data = pd.read_csv(file, encoding='cp1256')

        # التحقق من وجود بيانات
        if data.empty:
            st.error("الملف فارغ! يرجى تحميل ملف يحتوي على بيانات.")
            return None

        # عرض معلومات أولية عن البيانات


        # معالجة القيم المفقودة
        for column in data.columns:
            if data[column].isnull().any():
                if data[column].dtype in ['int64', 'float64']:
                    data[column].fillna(data[column].mean(), inplace=True)
                else:
                    data[column].fillna(data[column].mode()[0], inplace=True)

        # تحويل البيانات غير الرقمية
        for column in data.columns:
            if data[column].dtype == 'object':
                le = LabelEncoder()
                data[column] = le.fit_transform(data[column].astype(str))

        # معالجة عمود الهدف (العمود الأخير)
        target_column = data.columns[-1]
        unique_values = data[target_column].unique()

        # إذا كان هناك قيمة واحدة فقط، نقوم بإنشاء تصنيف ثنائي اصطناعي
        if len(unique_values) == 1:
            st.warning("""
            تم اكتشاف فئة واحدة فقط في عمود التصنيف. 
            سيتم إنشاء تصنيف ثنائي باستخدام التحليل الإحصائي للبيانات.
            """)

            # حساب المتوسط والانحراف المعياري لجميع الأعمدة العددية
            numeric_columns = data.select_dtypes(include=['int64', 'float64']).columns
            data_stats = data[numeric_columns].agg(['mean', 'std'])

            # إنشاء عمود تصنيف جديد بناءً على الانحراف عن المتوسط
            anomaly_scores = np.zeros(len(data))
            for col in numeric_columns:
                z_scores = np.abs((data[col] - data_stats.loc['mean', col]) / data_stats.loc['std', col])
                anomaly_scores += z_scores

            # تحديد عتبة للتصنيف (مثلاً: أعلى 20% من القيم تعتبر شاذة)
            threshold = np.percentile(anomaly_scores, 80)
            data[target_column] = (anomaly_scores > threshold).astype(int)

            st.info(f"""
            تم إنشاء تصنيف ثنائي:
            - 0: حركة طبيعية ({sum(data[target_column] == 0)} حالة)
            - 1: حركة غير طبيعية ({sum(data[target_column] == 1)} حالة)
            """)

        # تطبيع البيانات
        numeric_columns = data.select_dtypes(include=['int64', 'float64']).columns
        scaler = MinMaxScaler()
        data[numeric_columns] = scaler.fit_transform(data[numeric_columns])

        return data

    except Exception as e:
        st.error(f"حدث خطأ أثناء معالجة الملف: {str(e)}")
        return None


def prepare_data(data):
    """تجهيز البيانات للتدريب مع تصنيف متوازن باستخدام SMOTE"""
    try:
        if len(data.columns) < 2:
            st.error("يجب أن يحتوي الملف على عمودين على الأقل (المدخلات والهدف)")
            return None

        X = data.iloc[:, :-1]  # كل الأعمدة ما عدا العمود الأخير
        y = data.iloc[:, -1]  # العمود الأخير (التصنيف)

        # التحقق من عدد الفئات
        unique_classes = np.unique(y)

        if len(unique_classes) < 2:
            # إنشاء تصنيف ثنائي باستخدام تقنيات الكشف عن الشذوذ
            st.info("جاري إنشاء تصنيف ثنائي باستخدام تحليل الشذوذ...")

            # استخدام LOF للكشف عن الشذوذ
            lof = LocalOutlierFactor(contamination=0.1, novelty=False)
            y_artificial = lof.fit_predict(X)

            # تحويل -1 إلى 1 للحصول على تصنيف ثنائي (0, 1)
            y = np.where(y_artificial == -1, 1, 0)

            # عرض إحصائيات التصنيف الجديد
            st.success(f"""
            تم إنشاء تصنيف ثنائي:
            - الفئة 0 (طبيعي): {sum(y == 0)} حالة
            - الفئة 1 (شاذ): {sum(y == 1)} حالة
            """)

        # تطبيق SMOTE لموازنة البيانات
        smote = SMOTE(sampling_strategy='auto', random_state=42)
        X_resampled, y_resampled = smote.fit_resample(X, y)

        # تقسيم البيانات إلى تدريب واختبار
        X_train, X_test, y_train, y_test = train_test_split(
            X_resampled, y_resampled,
            test_size=0.2,
            random_state=42,
            stratify=y_resampled
        )

        # عرض معلومات عن تقسيم البيانات
        st.info(f"""
        إحصائيات تقسيم البيانات:
        - مجموعة التدريب: {len(X_train)} عينة
        - مجموعة الاختبار: {len(X_test)} عينة
        """)

        return X_train, X_test, y_train, y_test

    except Exception as e:
        st.error(f"خطأ في تجهيز البيانات: {str(e)}")
        return None

def create_balanced_classification(data):
    """إنشاء تصنيف متوازن باستخدام تقنيات متعددة للكشف عن الشذوذ"""

    def calculate_anomaly_scores(X):
        """حساب درجات الشذوذ باستخدام عدة طرق"""
        scores = {}

        try:
            # 1. التحليل الإحصائي (Z-score)
            z_scores = np.abs(stats.zscore(X, nan_policy='omit'))
            scores['statistical'] = np.mean(z_scores, axis=1)

            # 2. الكشف المعتمد على المسافة (LOF)
            lof = LocalOutlierFactor(n_neighbors=20, novelty=True)
            lof.fit(X)
            scores['lof'] = -lof.score_samples(X)

            # 3. الكشف المعتمد على الكثافة (DBSCAN)
            dbscan = DBSCAN(eps=0.5, min_samples=5)
            db_labels = dbscan.fit_predict(X)
            scores['dbscan'] = (db_labels == -1).astype(float)  # تحويل إلى float للتوافق

            return scores

        except Exception as e:
            st.error(f"خطأ في حساب درجات الشذوذ: {str(e)}")
            return None

    try:
        X = data.iloc[:, :-1]  # كل الأعمدة ما عدا الأخير

        # التأكد من عدم وجود قيم مفقودة
        X = X.fillna(X.mean())

        # تطبيع البيانات
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # حساب درجات الشذوذ
        anomaly_scores = calculate_anomaly_scores(X_scaled)

        if anomaly_scores is None:
            return None

        # دمج النتائج من مختلف الطرق
        combined_score = np.zeros(len(X))
        for method_name, scores in anomaly_scores.items():
            # تطبيع الدرجات
            if np.max(scores) > np.min(scores):
                normalized_scores = (scores - np.min(scores)) / (np.max(scores) - np.min(scores))
                combined_score += normalized_scores

        combined_score /= len(anomaly_scores)

        # تحديد عتبة ديناميكية
        threshold = np.percentile(combined_score, 85)  # اعتبار أعلى 15% كحالات شاذة

        # إنشاء التصنيف النهائي
        classifications = (combined_score > threshold).astype(int)

        # عرض إحصائيات التصنيف
        normal_count = sum(classifications == 0)
        anomaly_count = sum(classifications == 1)

        st.success(f"""
        تم إنشاء تصنيف متوازن بنجاح:
        - حركة طبيعية: {normal_count} حالة ({normal_count / len(classifications) * 100:.1f}%)
        - حركة غير طبيعية: {anomaly_count} حالة ({anomaly_count / len(classifications) * 100:.1f}%)

        تم استخدام:
        ✓ التحليل الإحصائي (Z-score)
        ✓ الكشف المعتمد على المسافة (LOF)
        ✓ الكشف المعتمد على الكثافة (DBSCAN)
        """)

        return classifications

    except Exception as e:
        st.error(f"خطأ في إنشاء التصنيف المتوازن: {str(e)}")
        return None

def evaluate_model(y_true, y_pred, model_name):
    """حساب مقاييس الأداء للنموذج"""
    acc = accuracy_score(y_true, y_pred) * 100
    rec = recall_score(y_true, y_pred, average='binary') * 100
    prec = precision_score(y_true, y_pred, average='binary') * 100
    f1 = f1_score(y_true, y_pred, average='binary') * 100

    return {
        "النموذج": model_name,
        "الدقة (%)": round(acc, 2),
        "الحساسية (%)": round(rec, 2),
        "الدقة التنبؤية (%)": round(prec, 2),
        "F1-Score (%)": round(f1, 2),
    }


import tensorflow as tf  # التأكد من استيراد TensorFlow
import pandas as pd
import numpy as np
import streamlit as st
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score, confusion_matrix
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv1D, MaxPooling1D, Flatten, LSTM, Dropout, BatchNormalization
from tensorflow.keras.callbacks import EarlyStopping

# ✅ **دالة مستقلة لتقييم النماذج**
def evaluate_model(y_true, y_pred, model_name):
    """حساب مقاييس الأداء للنموذج"""
    acc = accuracy_score(y_true, y_pred) * 100
    rec = recall_score(y_true, y_pred, average='binary') * 100
    prec = precision_score(y_true, y_pred, average='binary') * 100
    f1 = f1_score(y_true, y_pred, average='binary') * 100

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    false_positive_rate = (fp / (fp + tn)) * 100 if (fp + tn) > 0 else 0

    return {
        "النموذج": model_name,
        "الدقة (%)": round(acc, 2),
        "الحساسية (%)": round(rec, 2),
        "الدقة التنبؤية (%)": round(prec, 2),
        "F1-Score (%)": round(f1, 2),
        "معدل الإيجابيات الزائفة (%)": round(false_positive_rate, 2),
    }

# ✅ **تحديث `train_models`**
def train_models(X_train, X_test, y_train, y_test):
    """تدريب النماذج مع ضوابط وتحسينات لضمان نتائج أكثر دقة وموثوقية"""
    results = []
    trained_models = {}

    # SVM مع تحسين المعاملات
    with st.spinner('جاري تدريب نموذج SVM...'):
        try:
            svm_model = SVC(
                kernel='rbf',
                C=1.0,
                probability=True,
                class_weight='balanced',
                random_state=42
            )
            svm_model.fit(X_train, y_train)
            y_pred_svm = svm_model.predict(X_test)
            results.append(evaluate_model(y_test, y_pred_svm, "SVM"))
            trained_models['svm'] = svm_model
        except Exception as e:
            st.warning(f"⚠️ فشل تدريب SVM: {str(e)}")
            trained_models['svm'] = None

    # Decision Tree مع ضبط المعاملات
    with st.spinner('جاري تدريب نموذج Decision Tree...'):
        try:
            dt_model = DecisionTreeClassifier(
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight='balanced',
                random_state=42
            )
            dt_model.fit(X_train, y_train)
            y_pred_dt = dt_model.predict(X_test)
            results.append(evaluate_model(y_test, y_pred_dt, "Decision Tree"))
            trained_models['dt'] = dt_model
        except Exception as e:
            st.warning(f"⚠️ فشل تدريب Decision Tree: {str(e)}")
            trained_models['dt'] = None

    # CNN مع هيكلة محسنة
    with st.spinner('جاري تدريب نموذج CNN...'):
        try:
            X_train_cnn = np.expand_dims(X_train, axis=2)
            X_test_cnn = np.expand_dims(X_test, axis=2)

            cnn_model = Sequential([
                Conv1D(32, 3, activation='relu', input_shape=(X_train.shape[1], 1)),
                BatchNormalization(),
                MaxPooling1D(2),
                Dropout(0.2),

                Conv1D(64, 3, activation='relu'),
                BatchNormalization(),
                MaxPooling1D(2),
                Dropout(0.2),

                Flatten(),
                Dense(64, activation='relu'),
                BatchNormalization(),
                Dropout(0.3),
                Dense(1, activation='sigmoid')
            ])

            cnn_model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )

            # التدريب مع Early Stopping
            early_stopping = EarlyStopping(
                monitor='val_loss',
                patience=5,
                restore_best_weights=True
            )

            cnn_history = cnn_model.fit(
                X_train_cnn, y_train,
                epochs=50,
                batch_size=32,
                validation_split=0.2,
                callbacks=[early_stopping],
                verbose=0
            )

            y_pred_cnn = (cnn_model.predict(X_test_cnn) > 0.5).astype("int32").flatten()
            results.append(evaluate_model(y_test, y_pred_cnn, "CNN"))
            trained_models['cnn'] = {'model': cnn_model, 'X_test': X_test_cnn}

        except Exception as e:
            st.warning(f"⚠️ فشل تدريب CNN: {str(e)}")
            trained_models['cnn'] = None

    # RNN مع هيكلة محسنة
    with st.spinner('جاري تدريب نموذج RNN...'):
        try:
            X_train_rnn = np.expand_dims(X_train, axis=2)
            X_test_rnn = np.expand_dims(X_test, axis=2)

            rnn_model = Sequential([
                LSTM(32, return_sequences=True, input_shape=(X_train.shape[1], 1)),
                BatchNormalization(),
                Dropout(0.2),

                LSTM(64),
                BatchNormalization(),
                Dropout(0.2),

                Dense(32, activation='relu'),
                BatchNormalization(),
                Dropout(0.2),
                Dense(1, activation='sigmoid')
            ])

            rnn_model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
                loss='binary_crossentropy',
                metrics=['accuracy']
            )

            early_stopping = EarlyStopping(
                monitor='val_loss',
                patience=5,
                restore_best_weights=True
            )

            rnn_history = rnn_model.fit(
                X_train_rnn, y_train,
                epochs=50,
                batch_size=32,
                validation_split=0.2,
                callbacks=[early_stopping],
                verbose=0
            )

            y_pred_rnn = (rnn_model.predict(X_test_rnn) > 0.5).astype("int32").flatten()
            results.append(evaluate_model(y_test, y_pred_rnn, "RNN"))
            trained_models['rnn'] = {'model': rnn_model, 'X_test': X_test_rnn}

        except Exception as e:
            st.warning(f"⚠️ فشل تدريب RNN: {str(e)}")
            trained_models['rnn'] = None

    if not results:
        st.error("❌ فشل تدريب جميع النماذج!")
        return None, None

    return pd.DataFrame(results), trained_models

def main():
    st.title("نظام الكشف عن الهجمات السيبرانية باستخدام الذكاء الاصطناعي")

    # إضافة خيارات في الشريط الجانبي
    with st.sidebar:
        st.header("إعدادات النظام")
        st.write("---")

        # خيار استخدام نماذج مدربة مسبقاً
        use_saved_models = st.checkbox("استخدام نماذج مدربة مسبقاً")

        if use_saved_models and os.path.exists('trained_models'):
            # البحث عن النماذج المحفوظة
            model_folders = [f for f in os.listdir('trained_models') if f.startswith('models_')]

            if model_folders:
                selected_model = st.selectbox(
                    "اختر نموذج مدرب",
                    model_folders,
                    format_func=lambda x: f"نموذج {x.split('_')[1]}"
                )

                if selected_model:
                    model_path = os.path.join('trained_models', selected_model)
                    st.session_state['trained_models'] = load_models(model_path)
                    if st.session_state['trained_models']:
                        st.success("تم تحميل النماذج بنجاح!")
            else:
                st.warning("لا توجد نماذج محفوظة")

    st.write("---")

    # تحميل البيانات
    uploaded_file = st.file_uploader("رفع ملف CSV", type="csv")

    if uploaded_file is not None:
        # تحميل ومعالجة البيانات
        with st.spinner('جاري تحميل ومعالجة البيانات...'):
            data = load_and_preprocess_data(uploaded_file)

        if data is not None:
            st.success('تم تحميل ومعالجة البيانات بنجاح!')

            # عرض معاينة للبيانات
            if st.checkbox("عرض معاينة البيانات"):
                st.write("### معاينة البيانات")
                st.write(data.head())

            # عرض إحصائيات البيانات
            if st.checkbox("عرض إحصائيات البيانات"):
                st.write("### إحصائيات البيانات")
                st.write(data.describe())

            # تجهيز البيانات للتدريب
            data_split = prepare_data(data)

            if data_split is not None:
                X_train, X_test, y_train, y_test = data_split

                # زر تدريب النماذج
                if st.button("تدريب النماذج"):
                    results_df, models = train_models(X_train, X_test, y_train, y_test)

                    if results_df is not None and models is not None:
                        # حفظ النماذج في session_state
                        st.session_state['trained_models'] = models
                        st.session_state['test_data'] = X_test

                        # حفظ النماذج في ملفات
                        models_path = save_models(models)
                        if models_path:
                            st.success(f"تم حفظ النماذج بنجاح في المجلد: {models_path}")

                        # عرض نتائج التدريب في جدول
                        st.write("### نتائج تدريب النماذج")

                        # تنسيق الأرقام قبل عرض الجدول
                        results_df["الدقة (%)"] = results_df["الدقة (%)"].round(2)
                        results_df["الحساسية (%)"] = results_df["الحساسية (%)"].round(2)
                        results_df["الدقة التنبؤية (%)"] = results_df["الدقة التنبؤية (%)"].round(2)
                        results_df["F1-Score (%)"] = results_df["F1-Score (%)"].round(2)
                        results_df["معدل الإيجابيات الزائفة (%)"] = results_df["معدل الإيجابيات الزائفة (%)"].round(2)

                        st.dataframe(results_df)
                        st.success('تم تدريب جميع النماذج بنجاح!')

                # زر الكشف عن الهجمات
                if st.button("الكشف عن الهجمات"):
                    if 'trained_models' not in st.session_state:
                        st.warning("يرجى تدريب النماذج أولاً!")
                    else:
                        st.write("### نتائج الكشف عن الهجمات")

                        # إنشاء DataFrame لتخزين النتائج
                        detection_results = {
                            "النموذج": [],
                            "عدد التهديدات المكتشفة": [],
                            "نسبة التهديدات (%)": [],
                            "مستوى الخطورة": []
                        }

                        # SVM
                        with st.spinner('جاري تحليل النتائج باستخدام SVM...'):
                            svm_model = st.session_state['trained_models']['svm']
                            y_pred_svm = svm_model.predict(st.session_state['test_data'])
                            y_pred_proba_svm = svm_model.predict_proba(st.session_state['test_data'])[:, 1]

                            detection_results["النموذج"].append("SVM")
                            detection_results["عدد التهديدات المكتشفة"].append(int(sum(y_pred_svm)))
                            # تصحيح هنا
                            threat_percentage = round((sum(y_pred_svm) / len(y_pred_svm)) * 100, 2)
                            detection_results["نسبة التهديدات (%)"].append(threat_percentage)
                            detection_results["مستوى الخطورة"].append(
                                round(np.mean(y_pred_proba_svm[y_pred_svm == 1]) * 100, 2) if sum(y_pred_svm) > 0 else 0
                            )

                        # Decision Trees
                        with st.spinner('جاري تحليل النتائج باستخدام Decision Trees...'):
                            dt_model = st.session_state['trained_models']['dt']
                            y_pred_dt = dt_model.predict(st.session_state['test_data'])
                            y_pred_proba_dt = dt_model.predict_proba(st.session_state['test_data'])[:, 1]

                            detection_results["النموذج"].append("Decision Trees")
                            detection_results["عدد التهديدات المكتشفة"].append(int(sum(y_pred_dt)))
                            threat_percentage = round((sum(y_pred_dt) / len(y_pred_dt)) * 100, 2)
                            detection_results["نسبة التهديدات (%)"].append(threat_percentage)
                            severity = round(np.mean(y_pred_proba_dt[y_pred_dt == 1]) * 100, 2) if sum(
                                y_pred_dt) > 0 else 0
                            detection_results["مستوى الخطورة"].append(severity)

                            # CNN
                            with st.spinner('جاري تحليل النتائج باستخدام CNN...'):
                                cnn_data = st.session_state['trained_models']['cnn']
                                y_pred_cnn = (cnn_data['model'].predict(cnn_data['X_test']) > 0.5).astype("int32")
                                y_pred_proba_cnn = cnn_data['model'].predict(cnn_data['X_test'])

                                detection_results["النموذج"].append("CNN")
                                detection_results["عدد التهديدات المكتشفة"].append(int(np.sum(y_pred_cnn)))
                                # تصحيح حساب النسبة المئوية
                                threat_percentage = float(np.sum(y_pred_cnn) / len(y_pred_cnn) * 100)
                                detection_results["نسبة التهديدات (%)"].append(round(threat_percentage, 2))
                                # تصحيح حساب مستوى الخطورة
                                if np.sum(y_pred_cnn) > 0:
                                    severity = float(np.mean(y_pred_proba_cnn[y_pred_cnn == 1]) * 100)
                                    detection_results["مستوى الخطورة"].append(round(severity, 2))
                                else:
                                    detection_results["مستوى الخطورة"].append(0)

                            # RNN
                            with st.spinner('جاري تحليل النتائج باستخدام RNN...'):
                                rnn_data = st.session_state['trained_models']['rnn']
                                y_pred_rnn = (rnn_data['model'].predict(rnn_data['X_test']) > 0.5).astype("int32")
                                y_pred_proba_rnn = rnn_data['model'].predict(rnn_data['X_test'])

                                detection_results["النموذج"].append("RNN")
                                detection_results["عدد التهديدات المكتشفة"].append(int(np.sum(y_pred_rnn)))
                                # تصحيح حساب النسبة المئوية
                                threat_percentage = float(np.sum(y_pred_rnn) / len(y_pred_rnn) * 100)
                                detection_results["نسبة التهديدات (%)"].append(round(threat_percentage, 2))
                                # تصحيح حساب مستوى الخطورة
                                if np.sum(y_pred_rnn) > 0:
                                    severity = float(np.mean(y_pred_proba_rnn[y_pred_rnn == 1]) * 100)
                                    detection_results["مستوى الخطورة"].append(round(severity, 2))
                                else:
                                    detection_results["مستوى الخطورة"].append(0)

                        # عرض النتائج في جدول
                        results_df = pd.DataFrame(detection_results)

                        # تنسيق الأرقام قبل عرض الجدول
                        results_df["نسبة التهديدات (%)"] = results_df["نسبة التهديدات (%)"].round(2)
                        results_df["مستوى الخطورة"] = results_df["مستوى الخطورة"].round(2)

                        st.dataframe(results_df)

                        # إضافة قسم لتفاصيل التهديدات
                        st.write("### تفاصيل التهديدات المكتشفة")

                        # عرض تفاصيل لكل نموذج
                        for i, row in results_df.iterrows():
                            with st.expander(f"تفاصيل نموذج {row['النموذج']}"):
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.metric("عدد التهديدات", row["عدد التهديدات المكتشفة"])
                                    st.metric("نسبة التهديدات", f"{row['نسبة التهديدات (%)']:.2f}%")
                                with col2:
                                    st.metric("مستوى الخطورة", f"{row['مستوى الخطورة']:.2f}%")
                                    threat_level = "منخفض" if row['مستوى الخطورة'] < 50 else "متوسط" if row[
                                                                                                            'مستوى الخطورة'] < 75 else "مرتفع"
                                    st.metric("تصنيف الخطورة", threat_level)

                        # عرض الإحصائيات الرئيسية
                        col1, col2, col3, col4 = st.columns(4)

                        total_samples = len(st.session_state['test_data'])
                        high_risk_threats = sum([1 for risk in results_df["مستوى الخطورة"] if risk > 75])
                        potential_threats = results_df["عدد التهديدات المكتشفة"].mean()

                        with col1:
                            st.metric(
                                "عدد العينات المفحوصة",
                                f"{total_samples:,d}"
                            )

                        with col2:
                            st.metric(
                                "التهديدات المحتملة",
                                f"{int(potential_threats):,d}"
                            )

                        with col3:
                            st.metric(
                                "التهديدات عالية الخطورة",
                                f"{high_risk_threats:,d}"
                            )

                        with col4:
                            if st.button("تحميل التقرير 📊"):
                                # إنشاء تقرير مفصل
                                report = f"""تقرير تحليل التهديدات السيبرانية
تاريخ التحليل: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}

إحصائيات عامة:
-------------
عدد العينات المفحوصة: {total_samples}
إجمالي التهديدات المحتملة: {int(potential_threats)}
التهديدات عالية الخطورة: {high_risk_threats}

تفاصيل النماذج:
--------------
"""
                                for _, row in results_df.iterrows():
                                    report += f"""
نموذج {row['النموذج']}:
- عدد التهديدات: {row['عدد التهديدات المكتشفة']}
- نسبة التهديدات: {row['نسبة التهديدات (%)']}%
- مستوى الخطورة: {row['مستوى الخطورة']}%
"""

                                # تحويل التقرير إلى bytes
                                report_bytes = report.encode()

                                # تقديم التقرير للتحميل
                                st.download_button(
                                    label="تحميل التقرير الكامل",
                                    data=report_bytes,
                                    file_name=f"security_report_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.txt",
                                    mime="text/plain"
                                )

                        # تحليل النتائج وعرض التوصيات
                        st.write("### تحليل النتائج والتوصيات")

                        # حساب متوسط نسبة التهديدات من جميع النماذج
                        avg_threat_percentage = results_df["نسبة التهديدات (%)"].mean()
                        avg_threat_severity = results_df["مستوى الخطورة"].mean()

                        # تقييم مستوى الخطر العام
                        if avg_threat_percentage > 50 or avg_threat_severity > 75:
                            st.error("⚠️ تحذير: مستوى خطر مرتفع!")
                            st.markdown("""
                                **توصيات عاجلة:**
                                1. مراجعة جميع أنظمة الحماية وتحديثها فوراً
                                2. فحص جميع نقاط الوصول للشبكة
                                3. تفعيل إجراءات الطوارئ للأمن السيبراني
                                4. إبلاغ فريق الاستجابة للحوادث
                                """)
                        elif avg_threat_percentage > 25 or avg_threat_severity > 50:
                            st.warning("⚠️ تحذير: مستوى خطر متوسط")
                            st.markdown("""
                                **توصيات:**
                                1. مراقبة النشاط المشبوه عن كثب
                                2. تحديث أنظمة الحماية
                                3. مراجعة سجلات النظام
                                4. تعزيز إجراءات المراقبة
                                """)
                        else:
                            st.success("✓ مستوى الخطر منخفض")
                            st.markdown("""
                                **توصيات وقائية:**
                                1. الاستمرار في المراقبة الدورية
                                2. تحديث قواعد البيانات الأمنية
                                3. إجراء فحوصات أمنية دورية
                                """)


if __name__ == "__main__":
    main()