🛡️ CyberShield AI – Phishing Website Detector

📌 Project Overview

     CyberShield AI is a Python-based cybersecurity application designed to investigate website URLs and identify suspicious patterns that may indicate phishing       risks.
     
     The application provides an interactive dashboard to analyze URLs, calculate risk-indicator scores, review investigation history, and visualize security          findings. It combines rule-based URL analysis with an optional experimental Machine Learning model.

✨ Key Features

  🔎 **URL Investigation:** Analyze submitted website URLs for suspicious patterns.
  
  🛡️ **Risk Scoring:** Calculate a risk-indicator score from 0 to 100.
  
  🚩 **Suspicious Pattern Detection:** Identify unusual URL lengths, suspicious keywords, IP-based addresses, multiple hyphens, and other warning indicators.
  
  🔐 **HTTPS Analysis:** Check whether the URL uses HTTPS.
  
  🤖 **Experimental ML Prediction:** Use an optional Random Forest model for additional predictions.
  
  📊 **Risk Analysis Dashboard:** Visualize investigation results using interactive charts.

  🗃️ **Case Management:** Store and review previous URL investigations using SQLite.
  
  🔍 **Case Search:** Search saved records by URL, domain, or assessment.

  📥 **CSV Export:** Download investigation records and risk reports.
  
  🎨 **Interactive Interface:** Navigate through a dark-themed Streamlit dashboard.

🛠️ Technologies Used

    1. **Python** – Application logic and URL analysis
  
    2. **Streamlit** – Interactive web dashboard

    3. **Pandas** – Data processing and report generation

    4.**Scikit-learn** – Random Forest classification model
 
    5.**NumPy** – Numerical computing dependency
 
    6.**Plotly** – Interactive data visualization 
 
    7.**SQLite** – Investigation history database 
 
    8.**Pickle** – Saving and loading the trained ML model 
 
    9.**Regular Expressions** – URL pattern analysis

⚙️ How It Works

1. **Enter a URL:** The user submits a website URL for investigation.
2. **Normalize the URL:** The application adds an HTTPS prefix when no HTTP or HTTPS scheme is provided.
3. **Analyze URL Patterns:** It checks configured indicators such as URL length, HTTPS usage, suspicious keywords, IP addresses, and unusual URL structures.
4. **Calculate the Score:** Detected indicators contribute to a risk score between 0 and 100.
5. **Display the Assessment:** The application presents the score, assessment, and detected warning indicators.
6. **Save the Investigation:** The result is stored in the SQLite database.
7. **Review Reports:** Users can explore saved investigations, view charts, search records, and export CSV reports.

📊 Risk Assessment Levels

| Indicator Score | Assessment |
|---|---|
| 0–29 | LOW INDICATOR SCORE |
| 30–59 | SUSPICIOUS |
| 60–100 | HIGH RISK |

These levels represent configured URL warning indicators. They do not prove that a website is safe or malicious.


🚀 Installation and Setup

1. Clone the Repository


git clone https://github.com/divyashree2007-V/CyberShield-Phishing-Website-Detector


2. Open the Project Directory

cd CyberShield


3. Install Dependencies


python -m pip install -r requirements.txt


4. Run the Application


python -m streamlit run app.py


🤖 Training the Experimental ML Model

The project includes `train_model.py`, which trains a Random Forest classifier using a small, hard-coded sample dataset and saves the model as `phishing_model.pkl`.

To train the model, run:

python train_model.py




📈 Dashboard Modules

  **Security Overview:** View investigation statistics and perform a quick URL analysis.
  
  **Investigate URL:** Examine URL indicators and view the optional ML prediction.
  
  **Risk Analysis Report:** Explore risk distribution, recorded scores, and recurring warning patterns.
  
  **Case Files:** Search and review saved investigations and download records.
  
  **Project Notes:** View the project's objective, technologies, features, and limitations.

🎯 Project Objective

The objective of CyberShield AI is to demonstrate how Python, rule-based analysis, machine learning, data visualization, and database management can be combined to build a cybersecurity investigation dashboard.

The project also aims to increase awareness of suspicious website URLs and encourage safer browsing practices.

⚠️ Limitations

  1.The application analyzes URL patterns; it does not visit or crawl the target website.
  
  2.It does not currently check live threat-intelligence feeds or domain reputation.
  
  3.A low indicator score does not guarantee that a website is safe.
  
  4.A high indicator score does not prove that a website is malicious.
  
  5.The model's highest class probability is not a verified probability that a website is phishing.

🔮 Future Enhancements

  1.Train and evaluate the model using a larger, representative phishing URL dataset.
  
  2.Integrate trusted, real-time threat-intelligence services.
  
  3.Add domain reputation and certificate information checks.
  
  4.Improve URL feature extraction and model evaluation.
  
  5.Add automated alerts for high-risk indicators.
  
  6.Develop a browser extension for easier URL investigation.

👩‍💻 Developer

Divyashree V B.E. Computer Science and Engineering (Artificial Intelligence and Machine Learning)

  GitHub:https://github.com/divyashree2007-V
  
  LinkedIn: https://www.linkedin.com/in/divyashree-vijayan-9397a432b



