# ================================
# AI-Based Network Intrusion Detection System
# Final Working Code (PDF-Verified)
# ================================

import streamlit as st # pyright: ignore[reportMissingImports]
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns

# ---------------- PAGE CONFIG ----------------
st.set_page_config(page_title="AI NIDS Dashboard", layout="wide")

st.title("AI-Powered Network Intrusion Detection system")
st.markdown("""
This system uses **Machine Learning (Random Forest Algorithm)** to detect
malicious network traffic.

**Classes:**
- 0 → Benign (Normal Traffic)
- 1 → Malicious (Attack)
""")

# ---------------- DATA LOADING ----------------
@st.cache_data
def load_simulated_data():
    np.random.seed(42)
    n = 5000

    data = {
        "Destination_Port": np.random.randint(1, 65535, n),
        "Flow_Duration": np.random.randint(100, 100000, n),
        "Total_Fwd_Packets": np.random.randint(1, 50, n),
        "Packet_Length_Mean": np.random.uniform(10, 1500, n),
        "Active_Mean": np.random.uniform(1, 1000, n),
        "Label": np.random.choice([0, 1], n, p=[0.7, 0.3])
    }

    df = pd.DataFrame(data)

    # Attack patterns
    df.loc[df["Label"] == 1, "Total_Fwd_Packets"] += 100
    df.loc[df["Label"] == 1, "Flow_Duration"] = np.random.randint(1, 500, df[df["Label"] == 1].shape[0])

    return df


def load_real_data():
    df = pd.read_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    df = df[[
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Packet Length Mean",
        "Active Mean",
        "Label"
    ]]
    df.columns = [
        "Destination_Port",
        "Flow_Duration",
        "Total_Fwd_Packets",
        "Packet_Length_Mean",
        "Active_Mean",
        "Label"
    ]
    df["Label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)
    df.dropna(inplace=True)
    return df


# ---------------- SIDEBAR ----------------
st.sidebar.header("Settings")
data_mode = st.sidebar.radio("Select Data Mode", ["Simulation (Default)", "Real Dataset"])
train_size = st.sidebar.slider("Training Data (%)", 60, 90, 80)
trees = st.sidebar.slider("Random Forest Trees", 50, 200, 100)

# ---------------- LOAD DATA ----------------
if data_mode == "Simulation (Default)":
    df = load_simulated_data()
    st.info("Using simulated dataset (recommended for first run)")
else:
    try:
        df = load_real_data()
        st.success("Real CIC-IDS2017 dataset loaded successfully")
    except:
        st.error("Dataset file not found. Please place CSV in project folder.")
        st.stop()

# ---------------- PREPROCESS ----------------
X = df.drop("Label", axis=1)
y = df["Label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=(100 - train_size) / 100, random_state=42
)

# ---------------- TRAIN MODEL ----------------
st.divider()
st.subheader("Model Training")

if st.button("Train Model"):
    with st.spinner("Training Random Forest Model..."):
        model = RandomForestClassifier(n_estimators=trees, random_state=42)
        model.fit(X_train, y_train)
        st.session_state["model"] = model
        st.success("Model trained successfully!")

# ---------------- EVALUATION ----------------
st.divider()
st.subheader("Model Evaluation")

if "model" in st.session_state:
    model = st.session_state["model"]
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    st.metric("Accuracy", f"{acc * 100:.2f}%")

    st.text("Classification Report")
    st.text(classification_report(y_test, y_pred))

    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots()
    sns.heatmap(cm, annot=True, fmt="d", cmap="Reds", ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    st.pyplot(fig)
else:
    st.warning("Please train the model first.")

# ---------------- LIVE SIMULATOR ----------------
st.divider()
st.subheader("Live Traffic Analyzer")

c1, c2, c3, c4 = st.columns(4)
dur = c1.number_input("Flow Duration", 0, 100000, 500)
pkts = c2.number_input("Total Packets", 0, 500, 120)
plen = c3.number_input("Packet Length Mean", 0, 1500, 600)
active = c4.number_input("Active Mean", 0, 1000, 50)

if st.button("Analyze Traffic"):
    if "model" not in st.session_state:
        st.error("Train the model first")
    else:
        sample = np.array([[80, dur, pkts, plen, active]])
        result = st.session_state["model"].predict(sample)

        if result[0] == 1:
            st.error("🚨 MALICIOUS TRAFFIC DETECTED")
        else:
            st.success("✅ BENIGN TRAFFIC")
