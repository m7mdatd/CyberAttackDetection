# CyberAttackDetection

## 📌 Project Overview
CyberAttackDetection is a proactive AI-based system designed to detect cyber threats using machine learning and deep learning techniques. The system analyzes network traffic data, identifies potential threats, and improves over time through continuous learning.

## 🚀 Features
- **Machine Learning & Deep Learning Models**: Utilizes SVM, Random Forest, CNN, and RNN.
- **Real-time Threat Detection**: Detects cyber threats dynamically.
- **Database Logging**: Stores analyzed data in SQLite for historical analysis.
- **Automated Model Retraining**: Updates the model when new threats are detected.
- **Web UI with Streamlit**: Provides an easy-to-use interface for users to upload and analyze data.

## 🛠️ Installation
### **Prerequisites**
Ensure you have the following installed:
- Python 3.9+
- pip
- Git

### **Setup Instructions**
1. **Clone the repository:**
   ```bash
   git clone https://github.com/m7mdatd/CyberAttackDetection.git
   cd CyberAttackDetection
   ```
2. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
   ```
3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## 🔧 Running the System
### **1️⃣ Start the FastAPI Backend**
Run the backend server:
```bash
python api.py
```
The API will be available at: `http://127.0.0.1:8000`

### **2️⃣ Start the Streamlit Web UI**
Run the frontend interface:
```bash
streamlit run web_ui.py
```
The web interface will be available at: `http://localhost:8501`

## 📊 Using the System
1. Open the web interface.
2. Upload a CSV file containing network traffic data.
3. View the detected threats and system predictions.
4. If new threats are found, the system will retrain automatically.
5. Retrieve past logs using the `/logs` API.

## 🗃️ API Endpoints
### **1️⃣ Analyze Data**
- **Endpoint:** `POST /analyze`
- **Description:** Uploads and analyzes a CSV file for cyber threats.

### **2️⃣ Retrain Model**
- **Endpoint:** `POST /retrain`
- **Description:** Retrains the model using newly detected threats.

### **3️⃣ Fetch Logs**
- **Endpoint:** `GET /logs`
- **Description:** Retrieves past analysis records.

## 📝 License
This project is licensed under the MIT License.

## 👨‍💻 Author
Developed by **m7mdatd** - Feel free to reach out for any queries!

## ⭐ Contributions
Contributions are welcome! If you want to improve this project, feel free to submit a pull request.
