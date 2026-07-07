import os
import glob
import csv
from analyzer.pe_analyzer import analyze_pe

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

def collect_benign(max_files=150):
    samples = []
    exe_files = glob.glob(r"C:\Windows\System32\*.exe")[:max_files]
    
    for f in exe_files:
        try:
            result = analyze_pe(f)
            if "error" not in result:
                feat = extract_features(result)
                feat["label"] = 0
                samples.append(feat)
                print(f"[+] {result['file_name']}")
        except:
            pass
    return samples

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    
    print("=== 정상 샘플 수집 중 ===")
    benign = collect_benign()
    print(f"\n완료: {len(benign)}개 수집")
    
    with open("data/benign_features.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=benign[0].keys())
        writer.writeheader()
        writer.writerows(benign)
    
    print("data/benign_features.csv 저장 완료")