import streamlit as st
import pandas as pd
import sqlite3
import pickle
import os
import re
import json
import ipaddress
from urllib.parse import urlparse
from datetime import datetime
from collections import Counter

import plotly.express as px

st.set_page_config(
    page_title="CyberShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

DB_FILE = "cybershield_cases.db"
MODEL_FILE = "phishing_model.pkl"


# ---------------- DATABASE ----------------

def init_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            domain TEXT,
            score INTEGER,
            verdict TEXT,
            reasons TEXT,
            created_at TEXT,
            timestamp TEXT NOT NULL DEFAULT ''
        )
    """)

    cursor.execute("PRAGMA table_info(cases)")
    columns = [column[1] for column in cursor.fetchall()]

    if "domain" not in columns:
        cursor.execute("ALTER TABLE cases ADD COLUMN domain TEXT")

    if "score" not in columns:
        cursor.execute(
            "ALTER TABLE cases ADD COLUMN score INTEGER DEFAULT 0"
        )

    if "verdict" not in columns:
        cursor.execute("ALTER TABLE cases ADD COLUMN verdict TEXT")

    if "reasons" not in columns:
        cursor.execute("ALTER TABLE cases ADD COLUMN reasons TEXT")

    if "created_at" not in columns:
        cursor.execute("ALTER TABLE cases ADD COLUMN created_at TEXT")

    if "timestamp" not in columns:
        cursor.execute(
            "ALTER TABLE cases ADD COLUMN timestamp TEXT NOT NULL DEFAULT ''"
        )

    conn.commit()
    conn.close()
init_database()

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

st.write("DATABASE FILE:", os.path.abspath(DB_FILE))

cursor.execute("PRAGMA table_info(cases)")


conn.close()

def save_case(url, domain, score, verdict, reasons):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    parsed = urlparse(url)
    host = parsed.netloc or domain
    scheme = parsed.scheme or "https"

    reason_text = " | ".join(reasons)
    keyword_matches = ", ".join(
        word for word in [
            "login", "verify", "account", "password",
            "secure", "banking", "update", "confirm"
        ]
        if word in url.lower()
    )

    cursor.execute("""
        INSERT INTO cases (
            timestamp, url, host, score, verdict, scheme,
            length, keyword_matches, clues_json,
            evidence_json, action, domain, reasons, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        current_time,
        url,
        host,
        score,
        verdict,
        scheme,
        len(url),
        keyword_matches,
        json.dumps(reasons),
        json.dumps({"domain": domain, "score": score}),
        "Investigated",
        domain,
        reason_text,
        current_time
    ))

    conn.commit()
    conn.close()
def get_cases():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query(
        "SELECT * FROM cases ORDER BY id DESC", conn
    )
    conn.close()
    return df


init_database()


# ---------------- MODEL LOADING ----------------

@st.cache_resource
def load_model():
    if os.path.exists(MODEL_FILE):
        try:
            with open(MODEL_FILE, "rb") as file:
                return pickle.load(file)
        except Exception:
            return None
    return None


model = load_model()


# ---------------- URL ANALYSIS ----------------

def normalize_url(url):
    url = url.strip()

    if not url:
        return ""

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    return url


def analyze_url(raw_url):
    url = normalize_url(raw_url)

    if not url:
        return None

    parsed = urlparse(url)
    domain = parsed.netloc.lower().split("@")[-1]
    domain = domain.split(":")[0]
    
    score = 0
    reasons = []
    indicators = []

    def add_risk(points, message):
        nonlocal score
        score += points
        reasons.append(message)

    if parsed.scheme != "https":
        add_risk(15, "Website URL does not use HTTPS")

    if len(url) > 75:
        add_risk(10, "Unusually long URL")

    if len(url) > 120:
        add_risk(10, "Extremely long URL")

    if "@" in parsed.netloc:
        add_risk(25, "URL contains an @ symbol in its authority section")
    try:
        ipaddress.ip_address(domain)
        add_risk(25, "URL uses an IP address instead of a domain name")
    except ValueError:
        pass

    suspicious_words = [
        "login", "verify", "account", "update",
        "secure", "banking", "password", "confirm",
        "wallet", "payment", "signin", "free",
        "prize", "claim", "urgent", "suspended"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if found_words:
        add_risk(
            min(25, len(found_words) * 5),
            "Suspicious keywords: " + ", ".join(found_words)
        )

    if domain.count("-") >= 2:
        add_risk(10, "Domain contains multiple hyphens")

    if len(domain.split(".")) >= 5:
        add_risk(10, "Domain contains many subdomain levels")

    if "%" in url:
        add_risk(5, "URL contains encoded characters")

    if "//" in parsed.path:
        add_risk(10, "URL path contains repeated slashes")

    score = min(score, 100)

    if score >= 60:
        verdict = "HIGH RISK"
        color = "#ff4b4b"
    elif score >= 30:
        verdict = "SUSPICIOUS"
        color = "#ffa421"
    else:
        verdict = "LOW INDICATOR SCORE"
        color = "#21c55d"

    indicators.append({
        "Indicator": "URL Length",
        "Value": len(url)
    })
    indicators.append({
        "Indicator": "HTTPS",
        "Value": "Yes" if parsed.scheme == "https" else "No"
    })
    
    indicators.append({
        "Indicator": "Suspicious Keywords",
        "Value": len(found_words)
    })
    indicators.append({
        "Indicator": "Domain Length",
        "Value": len(domain)
    })

    if not reasons:
        reasons.append(
            "No configured URL warning patterns were detected"
        )

    return {
        "url": url,
        "domain": domain,
        "score": score,
        "verdict": verdict,
        "color": color,
        "reasons": reasons,
        "indicators": indicators,
        "found_words": found_words
    }


# ---------------- OPTIONAL ML PREDICTION ----------------

def get_ml_prediction(url):
    if model is None:
        return None

    parsed = urlparse(normalize_url(url))

    features = pd.DataFrame([{
        "url_length": len(url),
        "https": int(parsed.scheme == "https"),
        "suspicious": int(
            any(
                word in url.lower()
                for word in [
                    "login", "verify", "account", "password",
                    "secure", "banking", "update", "confirm"
                ]
            )
        )
    }])

    try:
        prediction = model.predict(features)[0]

        probability = None

        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(features)[0]
            probability = float(max(probabilities)) * 100

        return {
            "prediction": str(prediction),
            "probability": probability
        }

    except Exception:
        return None


# ---------------- CUSTOM STYLE ----------------


st.markdown("""
<style>
.stApp {
    background-color: #0b1020;
    color: #f8fafc;
}

.stApp p,
.stApp label,
.stApp li,
.stApp span,
.stApp div {
    color: #e2e8f0;
}

[data-testid="stSidebar"] {
    background-color: #111827;
}

[data-testid="stSidebar"] p,
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] span,
[data-testid="stSidebar"] div {
    color: #f1f5f9 !important;
}

[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 {
    color: #ffffff !important;
}

h1, h2, h3, h4 {
    color: #ffffff !important;
}

[data-testid="stMetricValue"] {
    color: #fbbf24 !important;
    font-weight: 800 !important;
}

[data-testid="stMetricLabel"] {
    color: #e2e8f0 !important;
}

.stMarkdown, .stCaption {
    color: #e2e8f0 !important;
}

[data-testid="stDataFrame"],
[data-testid="stTable"] {
    color: #111827;
}

.hero {
    padding: 26px;
    border-radius: 18px;
    background: linear-gradient(120deg, #172554, #312e81, #164e63);
    border: 1px solid #475569;
    margin-bottom: 22px;
}

.hero h1 {
    color: #ffffff !important;
    font-size: 34px;
    margin-bottom: 8px;
}

.hero p {
    color: #f1f5f9 !important;
    font-size: 16px;
}

.panel {
    padding: 20px;
    background: #111827;
    border: 1px solid #475569;
    border-radius: 14px;
    margin-bottom: 14px;
}

.small-note {
    color: #cbd5e1 !important;
    font-size: 13px;
}

button, [data-testid="stDownloadButton"] button {
    color: #ffffff !important;
}

input, textarea {
    color: #111827 !important;
}

</style>
""", unsafe_allow_html=True)

# ---------------- SIDEBAR ----------------

st.sidebar.markdown("# 🛡️ CyberShield AI")
st.sidebar.caption("URL Investigation & Risk Intelligence")

page = st.sidebar.radio(
    "NAVIGATION",
    [
        "🏠 Security Overview",
        "🔎 Investigate URL",
        "📊 Risk Analysis Report",
        "📁 Case Files",
        "📝 Project Notes"
    ]
)

st.sidebar.divider()

st.sidebar.markdown("### SYSTEM STATUS")
st.sidebar.write("🟢 Dashboard: Running")
st.sidebar.write(
    "🟢 ML Model: Loaded" if model is not None
    else "🟡 ML Model: Not loaded"
)

st.sidebar.caption(
    "Risk scores are heuristic indicators, not proof of malicious activity."
)


# ---------------- HERO ----------------

def show_hero(title, subtitle):
    st.markdown(
        f"""
        <div class="hero">
            <h1>{title}</h1>
            <p>{subtitle}</p>
        </div>
        """,
        unsafe_allow_html=True
    )


# ---------------- SECURITY OVERVIEW ----------------

if page == "🏠 Security Overview":

    show_hero(
        "CyberShield AI",
        "Intelligent URL investigation and suspicious-pattern analysis"
    )

    df = get_cases()

    total = len(df)

    high = (
        int((df["verdict"] == "HIGH RISK").sum())
        if total else 0
    )

    suspicious = (
        int((df["verdict"] == "SUSPICIOUS").sum())
        if total else 0
    )

    average = (
        round(df["score"].mean(), 1)
        if total else 0
    )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Investigations", total)
    c2.metric("High-Risk Indicators", high)
    c3.metric("Suspicious Results", suspicious)
    c4.metric("Average Risk Score", f"{average}/100")

    st.markdown("### ⚡ Quick Investigation")

    quick_url = st.text_input(
        "Enter a website URL",
        placeholder="https://example.com",
        key="overview_url"
    )

    if st.button("🔍 Analyze Website", use_container_width=True):
        if quick_url.strip():
            result = analyze_url(quick_url)

            if result:
                save_case(
                    result["url"],
                    result["domain"],
                    result["score"],
                    result["verdict"],
                    result["reasons"]
                )

                st.session_state["latest_result"] = result
                st.success("URL analysis completed.")
                st.rerun()
        else:
            st.warning("Please enter a URL.")

    if "latest_result" in st.session_state:
        result = st.session_state["latest_result"]

        st.markdown("### Latest Investigation")

        st.markdown(
            f"""
            <div class="panel">
                <h3>{result['verdict']}</h3>
                <p><b>Domain:</b> {result['domain']}</p>
                <p><b>Indicator Score:</b> {result['score']}/100</p>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.progress(result["score"] / 100)

        for reason in result["reasons"]:
            st.write("•", reason)

    st.markdown("### 🧭 Investigation Workflow")

    a, b, c = st.columns(3)

    a.markdown(
        "<div class='panel'><h4>01 · Capture</h4>"
        "Enter the URL you want to inspect.</div>",
        unsafe_allow_html=True
    )

    b.markdown(
        "<div class='panel'><h4>02 · Analyze</h4>"
        "Check configured suspicious URL patterns.</div>",
        unsafe_allow_html=True
    )

    c.markdown(
        "<div class='panel'><h4>03 · Investigate</h4>"
        "Review risk indicators and saved case records.</div>",
        unsafe_allow_html=True
    )

    st.caption(
        "This dashboard does not visit the target website or verify its live safety."
    )


# ---------------- INVESTIGATE URL ----------------

elif page == "🔎 Investigate URL":

    show_hero(
        "URL Investigation Lab",
        "Inspect URL structure and identify configured warning indicators"
    )

    url_input = st.text_input(
        "Target URL",
        placeholder="https://example.com/login"
    )

    analyze_button = st.button(
        "🚀 Run Investigation",
        type="primary",
        use_container_width=True
    )

    if analyze_button:

        if not url_input.strip():
            st.warning("Enter a URL before starting the investigation.")

        else:
            result = analyze_url(url_input)

            save_case(
                result["url"],
                result["domain"],
                result["score"],
                result["verdict"],
                result["reasons"]
            )

            st.session_state["latest_result"] = result

            st.markdown("### Investigation Result")

            m1, m2, m3 = st.columns(3)

            m1.metric("Indicator Score", f"{result['score']}/100")
            m2.metric("Assessment", result["verdict"])
            m3.metric("Domain Length", len(result["domain"]))

            st.progress(result["score"] / 100)

            st.markdown(
                f"""
                <div class="panel">
                    <h3 style="color:{result['color']}">
                        {result['verdict']}
                    </h3>
                    <p><b>Submitted URL:</b> {result['url']}</p>
                    <p><b>Extracted Domain:</b> {result['domain']}</p>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.markdown("### 🚩 Detected Indicators")

            for reason in result["reasons"]:
                st.write("⚠️", reason)

            st.markdown("### 🧬 URL Fingerprint")

            fingerprint_df = pd.DataFrame(result["indicators"])

            st.dataframe(
                fingerprint_df,
                use_container_width=True,
                hide_index=True
            )

            st.markdown("### 🤖 Experimental ML Model")

            ml_result = get_ml_prediction(result["url"])

            if ml_result:
                st.write(
                    "Model prediction:",
                    ml_result["prediction"]
                )

                if ml_result["probability"] is not None:
                    st.write(
                        "Model's highest class probability:",
                        f"{ml_result['probability']:.1f}%"
                    )

                st.caption(
                    "This model output is experimental. Its probability is not a "
                    "verified probability that the website is phishing."
                )
            else:
                st.info(
                    "ML prediction unavailable. Check that phishing_model.pkl "
                    "exists and is compatible with the current feature names."
                )

            st.warning(
                "This is a rule-based URL assessment with an optional experimental "
                "model. It does not check live threat feeds, website content, "
                "domain reputation, or actual browser behavior."
            )


# ---------------- RISK ANALYSIS REPORT ----------------

elif page == "📊 Risk Analysis Report":

    show_hero(
        "Risk Intelligence Report",
        "Explore saved investigation results and recurring warning patterns"
    )

    df = get_cases()

    if df.empty:
        st.info("No investigation records yet. Analyze a URL first.")

    else:
        total = len(df)
        high = int((df["verdict"] == "HIGH RISK").sum())
        suspicious = int((df["verdict"] == "SUSPICIOUS").sum())
        low = int((df["verdict"] == "LOW INDICATOR SCORE").sum())

        c1, c2, c3, c4 = st.columns(4)

        c1.metric("Total Cases", total)
        c2.metric("High Risk", high)
        c3.metric("Suspicious", suspicious)
        c4.metric("Low Indicator Score", low)

        st.markdown("### 📈 Risk Distribution")

        distribution = (
            df["verdict"]
            .value_counts()
            .rename_axis("Assessment")
            .reset_index(name="Cases")
        )

        fig = px.pie(
            distribution,
            names="Assessment",
            values="Cases",
            hole=0.55,
            title="Investigation Assessment Distribution"
        )

        st.plotly_chart(fig, use_container_width=True)

        st.markdown("### 🌐 Highest Recorded Indicator Scores")

        host_scores = (
            df.groupby("domain", as_index=False)["score"]
            .max()
            .sort_values("score", ascending=False)
            .head(10)
        )

        if not host_scores.empty:
            fig2 = px.bar(
                host_scores,
                x="domain",
                y="score",
                title="Maximum Recorded Score by Domain",
                labels={
                    "domain": "Domain",
                    "score": "Indicator Score"
                }
            )

            fig2.update_layout(yaxis_range=[0, 100])

            st.plotly_chart(fig2, use_container_width=True)

        st.markdown("### 🚩 Repeated Warning Patterns")

        reasons = []

        for text in df["reasons"].dropna():
            reasons.extend(
                item.strip()
                for item in text.split("|")
                if item.strip()
            )

        if reasons:
            reason_counts = Counter(reasons)

            reasons_df = pd.DataFrame(
                reason_counts.most_common(10),
                columns=["Warning Pattern", "Occurrences"]
            )

            st.dataframe(
                reasons_df,
                use_container_width=True,
                hide_index=True
            )

        st.markdown("### 🗂️ Investigation Records")

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True
        )

        csv_data = df.to_csv(index=False).encode("utf-8")

        st.download_button(
            "⬇️ Export Report as CSV",
            data=csv_data,
            file_name="cybershield_risk_report.csv",
            mime="text/csv",
            use_container_width=True
        )


# ---------------- CASE FILES ----------------

elif page == "📁 Case Files":

    show_hero(
        "Investigation Case Files",
        "Review previously saved URL investigations"
    )

    df = get_cases()

    if df.empty:
        st.info("No cases saved yet.")

    else:
        search = st.text_input(
            "Search by URL, domain, or assessment"
        )

        filtered = df.copy()

        if search.strip():
            mask = (
                filtered["url"].str.contains(
                    search, case=False, na=False
                )
                | filtered["domain"].str.contains(
                    search, case=False, na=False
                )
                | filtered["verdict"].str.contains(
                    search, case=False, na=False
                )
            )

            filtered = filtered[mask]

        st.write(f"Records found: {len(filtered)}")

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True
        )

        st.download_button(
            "⬇️ Download Case Files",
            data=filtered.to_csv(index=False).encode("utf-8"),
            file_name="cybershield_case_files.csv",
            mime="text/csv"
        )


# ---------------- PROJECT NOTES ----------------

elif page == "📝 Project Notes":

    show_hero(
        "Project Intelligence Notes",
        "Documentation, scope, limitations, and technical details"
    )

    st.markdown("### 🎯 Project Objective")

    st.write(
        "CyberShield AI is a URL investigation dashboard that identifies "
        "configured suspicious URL patterns and stores investigation records."
    )

    st.markdown("### ⚙️ Technologies Used")

    st.markdown("""
    - **Python** — core programming language
    - **Streamlit** — interactive dashboard
    - **Pandas** — data handling and reports
    - **Plotly** — interactive charts
    - **SQLite** — investigation history
    - **Scikit-learn model** — optional experimental prediction
    """)

    st.markdown("### 🔍 Current Features")

    st.markdown("""
    - URL structure analysis
    - Suspicious keyword detection
    - HTTPS and IP-address indicators
    - URL risk-indicator scoring
    - Optional saved ML model prediction
    - SQLite investigation history
    - Risk distribution charts
    - Warning-pattern analysis
    - CSV report export
    """)

    st.markdown("### ⚠️ Limitations")

    st.markdown("""
    - A low score does not prove a website is safe.
    - A high score does not prove a website is malicious.
    - The application does not currently query live threat intelligence.
    - The application does not open or crawl the target website.
    - An ML model trained on synthetic examples may not generalize to real URLs.
    - Never enter passwords or confidential information into a suspicious website.
    """)

    st.markdown("### 🛠️ Run the Project")

    st.code(
        "python -m pip install streamlit pandas plotly scikit-learn\n"
        "python -m streamlit run app.py",
        language="bash"
    )

    st.caption(
        "Only investigate URLs in ways that do not expose personal or confidential data."
    )