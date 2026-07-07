import math
import os

import pefile


def calculate_entropy(data):
    if not data:
        return 0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def analyze_pe(file_path):
    result = {
        "file_name": os.path.basename(file_path),
        "file_size": os.path.getsize(file_path),
        "sections": [],
        "imports": [],
        "overall_entropy": 0
    }
    try:
        pe = pefile.PE(file_path)

        # 섹션 분석
        for section in pe.sections:
            data = section.get_data()
            result["sections"].append({
                "name": section.Name.decode(errors="replace").strip("\x00"),
                "entropy": calculate_entropy(data),
                "size": section.SizeOfRawData
            })

        # 임포트 테이블
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="replace")
                funcs = [imp.name.decode(errors="replace") 
                         for imp in entry.imports if imp.name]
                result["imports"].append({"dll": dll, "functions": funcs})

        # 전체 엔트로피
        with open(file_path, "rb") as f:
            result["overall_entropy"] = calculate_entropy(f.read())

    except Exception as e:
        result["error"] = str(e)

    return result

if __name__ == "__main__":
    import json
    test_file = input("PE 파일 경로 입력: ").strip()
    report = analyze_pe(test_file)
    print(json.dumps(report, indent=2, ensure_ascii=False)) 
