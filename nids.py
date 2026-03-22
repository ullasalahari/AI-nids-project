# ================================
# AI-Based Network Intrusion Detection System
# FINAL CODE FOR YOUR DATASET
# ================================

import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns

# ---------------- PAGE CONFIG ----------------
st.set_page_config(page_title="AI NIDS Dashboard", layout="wide")

st.title("AI-Powered Network Intrusion Detection System")
st.markdown("""
This system uses **Machine Learning (Random Forest Algorithm)** to detect malicious traffic.

**Classes:**
- 0 → Benign  
- 1 → Malicious (DDoS)
""")

# ---------------- LOAD YOUR DATASET ----------------
def load_real_data():
    df = pd.read_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

    # Rename columns properly
    df.columns = [
        "Flow_Duration",
        "Total_Packets",
        "Total_Backward_Packets",
        "Packet_Length_Mean",
        "Label"
    ]

    # Convert labels to numbers
    df["Label"] = df["Label"].apply(lambda x: 0 if x.strip() == "Benign" else 1)

    df.dropna(inplace=True)
    return df

# ---------------- SIDEBAR ----------------
st.sidebar.header("Settings")
train_size = st.sidebar.slider("Training Data (%)", 60, 90, 80)
trees = st.sidebar.slider("Random Forest Trees", 50, 200, 100)

# ---------------- LOAD DATA ----------------
try:
    df = load_real_data()
    st.success("Dataset loaded successfully ✅")
except Exception as e:
    st.error(f"Error loading dataset: {e}")
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
    with st.spinner("Training model..."):
        model = RandomForestClassifier(n_estimators=trees, random_state=42)
        model.fit(X_train, y_train)
        st.session_state["model"] = model
        st.success("Model trained successfully! 🎉")

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

# ---------------- LIVE ANALYZER ----------------
st.divider()
st.subheader("Live Traffic Analyzer")

c1, c2, c3, c4 = st.columns(4)

dur = c1.number_input("Flow_Duration", 0, 10000, 1000)
pkts = c2.number_input("Total_Packets", 0, 200, 20)
bpkts = c3.number_input("Backward_Packets", 0, 200, 10)
plen = c4.number_input("Packet_Length Mean", 0, 1500, 300)

if st.button("Analyze Traffic"):
    if "model" not in st.session_state:
        st.error("Train the model first ❌")
    else:
        sample = np.array([[dur, pkts, bpkts, plen]])
        result = st.session_state["model"].predict(sample)

        if result[0] == 1:
            st.error("🚨 MALICIOUS TRAFFIC DETECTED")
        else:
            st.success("✅ BENIGN TRAFFIC")
