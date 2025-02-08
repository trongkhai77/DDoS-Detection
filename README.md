# DDoS Detection System with ONOS SDN Controller

## Giới thiệu
Hệ thống phát hiện tấn công DDoS sử dụng ONOS SDN Controller kết hợp với Machine Learning. Hệ thống thu thập dữ liệu lưu lượng mạng thông qua ONOS app và sử dụng mô hình ML để phân tích, phát hiện các dấu hiệu tấn công DDoS.

## Yêu cầu hệ thống
- ONOS Controller 2.0.0
- Mininet
- Python 3.x
- Maven
- FastAPI (uvicorn)

## Hướng dẫn cài đặt và sử dụng

### 1. Cài đặt môi trường
Cài đặt và khởi chạy ONOS 2.0.0 và Mininet theo hướng dẫn trong file `installOnos.txt`.

### 2. Cài đặt ONOS App
ONOS App có chức năng ghi lại lưu lượng mạng và xuất ra file CSV sau mỗi 10 giây.

```bash
# Di chuyển vào thư mục ddosdetection
cd ddosdetection

# Cài đặt app
sudo mvn clean install

# Copy file .oar vào thư mục apps của ONOS
sudo cp target/ddosdetection-2.0.0.oar /opt/onos/apps/
```

### 3. Cài đặt App trên ONOS Controller
```bash
# Cài đặt app
app install file:/opt/onos/apps/ddosdetection-2.0.0.oar

# Kích hoạt app
app activate org.ddosdetection.app
```

### 4. Khởi động ML API Service
API service được sử dụng để tải và chạy mô hình machine learning đã được huấn luyện.

```bash
uvicorn ddos_api:app --reload
```

### 5. Khởi động Data Collection Service
Mở terminal mới và chạy script thu thập dữ liệu:

```bash
python3 data.py
```

## Cấu trúc thư mục
```
.
├── /opt/
│   ├── ddosdetection/    # ONOS App source code
│   │   ├── src/         # Source code của ứng dụng
│   │   ├── target/      # Thư mục chứa file build
│   │   └── pom.xml      # File cấu hình Maven
│   └── onos/
│       ├── apps/
│       │   └── ddosdetection.oar  # ONOS app package đã build
│       └── bin/
│           └── topology.py   # Script tạo topology
└── ~/Desktop/
    ├── ddos_api.py      # FastAPI service cho ML model
    ├── data.py          # Script thu thập dữ liệu
    ├── knn_model.joblib # Model KNN đã train
    └── rf_model.joblib  # Model Random Forest đã train
```

