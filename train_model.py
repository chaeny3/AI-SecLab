import pickle

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

# 데이터 로드
benign = pd.read_csv("data/benign_features.csv")
malware = pd.read_csv("data/malware_features.csv")
df = pd.concat([benign, malware], ignore_index=True).sample(frac=1, random_state=42)

X = df.drop("label", axis=1)
y = df["label"]

# 학습/테스트 분리
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 모델 학습
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 평가
y_pred = model.predict(X_test)
print("=== 분류 결과 ===")
print(classification_report(y_test, y_pred, target_names=["정상", "악성"]))

# 혼동 행렬 시각화
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["정상", "악성"], yticklabels=["정상", "악성"])
plt.title("Confusion Matrix")
plt.ylabel("실제")
plt.xlabel("예측")
plt.tight_layout()
plt.savefig("models/confusion_matrix.png")
plt.show()
print("models/confusion_matrix.png 저장 완료")

# 모델 저장
with open("models/pe_classifier.pkl", "wb") as f:
    pickle.dump(model, f)
print("models/pe_classifier.pkl 저장 완료")