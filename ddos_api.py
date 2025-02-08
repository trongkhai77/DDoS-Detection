from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import numpy as np
import joblib
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
app = FastAPI(title="DDoS Detection API")
# Định nghĩa model cho input data
class TrafficData(BaseModel):
    Time: float
    Protocol: int
    Length: int
class BatchPredictRequest(BaseModel):
    data: List[TrafficData]
# Load pre-trained models
try:
    knn_model = joblib.load('knn_model.joblib')
    rf_model = joblib.load('rf_model.joblib')
    print("Loaded pre-trained models successfully")
except Exception as e:
    print(f"Error loading models: {e}")
    # Initialize new models if loading fails
    knn_model = KNeighborsClassifier(n_neighbors=3)
    rf_model = RandomForestClassifier(random_state=0)
# Khởi tạo window size và buffer cho dữ liệu
WINDOW_SIZE = 3
data_buffer = []
def create_sequence(data, window_size=WINDOW_SIZE):
    """Tạo chuỗi input cho model từ dữ liệu"""
    if len(data) < window_size:
        return None

    # Lấy window_size phần tử cuối cùng
    sequence = data[-window_size:]
    return np.array(sequence).reshape(1, -1)
def process_predictions(knn_pred, rf_pred):
    """Xử lý và kết hợp các dự đoán từ cả hai model"""
    # Nếu một trong hai model dự đoán là có tấn công (1), coi như có tấn công
    if knn_pred == 1 or rf_pred == 1:
        return "Đang bị tấn công DDoS"
    return "Bình thường"
@app.post("/predict_batch")
async def predict_batch(request: List[dict]):
    try:
        # Chuyển đổi dữ liệu đầu vào thành label
        for item in request:
            # Thêm logic để chuyển đổi dữ liệu thành label (0 hoặc 1)
            # Ví dụ: Nếu Protocol là ICMP và Length lớn, có thể là DDoS
            label = 1 if (item['Length'] > 1000) else 0
            data_buffer.append(label)
        # Giữ buffer size phù hợp
        if len(data_buffer) > WINDOW_SIZE * 2:
            data_buffer.pop(0)
        # Tạo sequence cho prediction
        sequence = create_sequence(data_buffer)
        if sequence is None:
            return {"status": "Chưa đủ dữ liệu", "details": "Đang thu thập..."}
        # Dự đoán từ cả hai model
        knn_prediction = knn_model.predict(sequence)[0]
        rf_prediction = rf_model.predict(sequence)[0]
        # Xử lý kết quả
        result = process_predictions(knn_prediction, rf_prediction)

        details = {
            "knn_prediction": int(knn_prediction),
            "rf_prediction": int(rf_prediction),
            "data_points_processed": len(request),
            "current_buffer_size": len(data_buffer)
        }
        return {
            "status": result,
            "details": details
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@app.get("/health")
async def health_check():
    return {"status": "healthy"}
if __name__ == "main":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
