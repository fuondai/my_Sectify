# run.py
import uvicorn
import os
from dotenv import load_dotenv

# Tải các biến môi trường từ tệp .env
load_dotenv()

if __name__ == "__main__":
    # Lấy host và port từ biến môi trường hoặc dùng giá trị mặc định
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", 8000))
    
    # reload=True giúp tự động tải lại server khi có thay đổi code
    # rất hữu ích trong môi trường development
    uvicorn.run("app.main:app", host=host, port=port, reload=True)
