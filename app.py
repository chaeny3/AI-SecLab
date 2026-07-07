import os
import pickle

import pandas as pd
from flask import Flask, jsonify, render_template, request

from analyzer.pe_analyzer import analyze_pe

app = Flask(__name__)

with open("models/pe_classifier.pkl", "rb") as f:
    model = pickle.load(f)

def extract_features(pe_result):
    sections = pe_result.get("sections", [])
    imports = pe_result.get("imports", [])
    all_funcs = [f for dll in imports for f in dll.get("functions", [])]
    return {
        "file_size": pe_result.get("file_size", 0),
        "overall_entropy": pe_result.get("overall_entropy", 0),
        "num_sections": len(sections),
        "avg_entropy": round(sum(s["entropy"] for s in sections) / len(sections), 4) if sections else 0,
        "max_entropy": max((s["entropy"] for s in sections), default=0),
        "num_dlls": len(imports),
        "num_functions": len(all_funcs),
    }

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "파일 없음"}), 400
    file = request.files["file"]
    if not file.filename.endswith(".exe"):
        return jsonify({"error": ".exe 파일만 가능"}), 400
    save_path = os.path.join("data", "upload_temp.exe")
    file.save(save_path)
    pe_result = analyze_pe(save_path)
    if "error" in pe_result:
        return jsonify({"error": pe_result["error"]}), 400
    features = extract_features(pe_result)
    df = pd.DataFrame([features])
    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0]
    return jsonify({
        "filename": file.filename,
        "prediction": "악성" if prediction == 1 else "정상",
        "malware_prob": round(float(probability[1]) * 100, 1),
        "features": features,
        "sections": pe_result.get("sections", [])
    })

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")