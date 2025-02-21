# CyberAttackDetection

image.png

## Overview
This project implements an advanced cybersecurity attack detection system using artificial intelligence and machine learning techniques. The system utilizes multiple AI models including Support Vector Machines (SVM), Decision Trees, Convolutional Neural Networks (CNN), and Recurrent Neural Networks (RNN) to detect and classify potential cyber threats.

## Features
- **Multi-Model Analysis**: Combines results from four different AI models:
  - Support Vector Machine (SVM)
  - Decision Trees
  - Convolutional Neural Network (CNN)
  - Recurrent Neural Network (RNN)
- **Automated Data Processing**: Handles data preprocessing, including:
  - Missing value imputation
  - Feature scaling
  - Label encoding
  - Automated binary classification creation
- **Advanced Model Training**: Implements sophisticated training procedures with:
  - SMOTE for handling imbalanced datasets
  - Early stopping to prevent overfitting
  - Batch normalization
  - Dropout layers for better generalization
- **Comprehensive Evaluation Metrics**:
  - Accuracy
  - Precision
  - Recall
  - F1-Score
  - False Positive Rate
- **Interactive UI**: Built with Streamlit for easy interaction and visualization
- **Model Management**: Support for saving and loading trained models
- **Detailed Reporting**: Generates comprehensive threat analysis reports

## Requirements
```
streamlit
pandas
numpy
scikit-learn
tensorflow
scipy
joblib
imbalanced-learn
```

## Installation
1. Clone the repository:
```bash
git clone https://github.com/yourusername/cybersecurity-ai-detection.git
cd cybersecurity-ai-detection
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage
1. Start the application:
```bash
streamlit run app.py
```

2. Upload your CSV data file containing network traffic or security-related features

3. Choose your preferred options:
   - Use pre-trained models
   - Train new models
   - Analyze threats
   - Generate reports

## Input Data Format
The system expects a CSV file with:
- Numerical and/or categorical features related to network traffic or security events
- The last column should be the target variable (can be binary or multi-class)
- Missing values are handled automatically

## Model Architecture

### CNN Model
- Input layer with appropriate shape
- Multiple Conv1D layers with BatchNormalization
- MaxPooling layers
- Dropout layers for regularization
- Dense layers for final classification

### RNN Model
- LSTM layers with BatchNormalization
- Dropout layers
- Dense layers for output
- Binary cross-entropy loss function

### Traditional Models
- SVM with RBF kernel
- Decision Tree with optimized parameters

## Output and Reporting
The system provides:
- Real-time threat detection results
- Threat severity levels
- Detailed analysis per model
- Downloadable comprehensive reports
- Visual representations of results
- Actionable security recommendations

## Error Handling
- Robust error handling for file operations
- Graceful handling of model training failures
- Comprehensive error messages
- Automatic data validation

## Security Recommendations
The system provides automated recommendations based on threat levels:
- High Risk: Emergency security protocols
- Medium Risk: Enhanced monitoring procedures
- Low Risk: Preventive measures

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
This project is licensed under the MIT License.

## Contact
Developed by Mohammed Almawi - Feel free to reach out for any queries! 444805745@ub.edu.sa

## Note
This system is designed for educational and research purposes. Always follow appropriate security protocols and guidelines in production environments.
