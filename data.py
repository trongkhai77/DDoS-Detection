from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pandas as pd
import requests
import time
import os
import numpy as np
from datetime import datetime

# API endpoint
API_URL = "http://localhost:8000/predict_batch"
MERGED_FILE_PATH = "/home/khai/Desktop/merged_data/merged_traffic.csv"

class CSVHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_modified = 0
        self.last_size = 0

    def on_modified(self, event):
        if event.src_path != MERGED_FILE_PATH:
            return

        # Thêm một khoảng delay nhỏ để đảm bảo file đã được ghi hoàn tất
        time.sleep(0.5)

        try:
            current_size = os.path.getsize(MERGED_FILE_PATH)
            current_modified = os.path.getmtime(MERGED_FILE_PATH)
            
            # Chỉ xử lý khi file thực sự thay đổi
            if current_modified != self.last_modified and current_size != self.last_size:
                self.last_modified = current_modified
                self.last_size = current_size
                self.process_file()
        except OSError as e:
            print(f"Lỗi khi kiểm tra file: {e}")

    def process_file(self):
        try:
            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Đang xử lý dữ liệu mới...")
            
            # Đảm bảo file tồn tại và không trống
            if not os.path.exists(MERGED_FILE_PATH) or os.path.getsize(MERGED_FILE_PATH) == 0:
                print("File không tồn tại hoặc trống")
                return

            try:
                # Đọc file với on_bad_lines='skip' để bỏ qua các dòng lỗi
                df = pd.read_csv(MERGED_FILE_PATH, on_bad_lines='skip')
            except pd.errors.EmptyDataError:
                print("File CSV trống")
                return
            except Exception as e:
                print(f"Lỗi khi đọc file CSV: {e}")
                return

            if df.empty:
                print("Không có dữ liệu trong file")
                return

            print(f"Đã đọc được {len(df)} bản ghi")

            # Xử lý dữ liệu
            protocol_mapping = {
                'ICMP': 1,
                'TCP': 6,
                'UDP': 17,
                'LLDP': 2,
                'ARP': 3,
                'ICMPv6': 4,
                'MDNS': 5,
                'Unknown': 0
            }
            
            # Chuyển đổi Protocol và xử lý các giá trị không hợp lệ
            df['Destination'] = df['Destination'].map(protocol_mapping).fillna(0).astype(int) #Protocol
            
            # Chuyển đổi Length và xử lý các giá trị không hợp lệ
            df['Protocol'] = pd.to_numeric(df['Protocol'], errors='coerce').fillna(0).astype(int) #Lenght
            
            # Chuyển đổi Time
            df['No.'] = pd.to_numeric(df['No.'], errors='coerce').fillna(0) #Time

            # Chuẩn bị dữ liệu cho API
            data = [{
                'Time': float(row['No.']),
                'Protocol': int(row['Destination']),
                'Length': int(row['Protocol'])
            } for index, row in df.iterrows()]

            print(f"Gửi {len(data)} bản ghi lên API...")

            # Gửi request tới API
            try:
                response = requests.post(API_URL, json=data, timeout=10)
                
                print(f"Status Code: {response.status_code}")
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('status') == 'Đang bị tấn công DDoS':
                        print("\n🚨 CẢNH BÁO: Phát hiện tấn công DDoS! 🚨")
                        print(f"Chi tiết: {result.get('details', 'Không có thông tin chi tiết')}")
                    else:
                        print("\n✅ Hệ thống an toàn, không phát hiện tấn công.")
                else:
                    print(f"\n❌ Lỗi khi gửi dữ liệu lên API: HTTP {response.status_code}")
                    print(f"Chi tiết lỗi: {response.text}")
                    
            except requests.exceptions.RequestException as e:
                print(f"\n❌ Lỗi kết nối đến API: {e}")
                
        except Exception as e:
            print(f"\n❌ Lỗi không xác định: {e}")
            import traceback
            print(traceback.format_exc())

def main():
    print(f"Starting DDoS Detection Monitor...")
    print(f"Monitoring file: {MERGED_FILE_PATH}")
    print("Waiting for file updates...")

    # Tạo thư mục cha nếu chưa tồn tại
    os.makedirs(os.path.dirname(MERGED_FILE_PATH), exist_ok=True)

    event_handler = CSVHandler()
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(MERGED_FILE_PATH), recursive=False)
    
    try:
        observer.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        observer.stop()
    except Exception as e:
        print(f"Error: {e}")
        observer.stop()
    finally:
        observer.join()

if __name__ == "__main__":
    main()
