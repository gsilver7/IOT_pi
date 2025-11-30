import os
import sys
import io
import numpy as np
from PIL import Image
from face_recognition_module import FaceVectorExtractor, VectorStorage

def main():
    # 현재 파일이 있는 폴더 경로
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 1. 초기 설정
    # 주의: FaceVectorExtractor가 '이미지 경로(str)'가 아닌 '이미지 배열(numpy array)'을 받을 수 있어야 합니다.
    extractor = FaceVectorExtractor(model="hog")
    storage = VectorStorage(storage_dir="/home/rlaaudwns/web/backend/src/python/face_vectors")
    
    # 2. 커맨드라인 인자 처리 (이미지 경로는 stdin으로 받으므로 user_id만 받음)
    if len(sys.argv) < 2:
        print("사용법: python face_main.py <user_id>")
        # 이미지는 파이프(stdin)로 전달받습니다.
        sys.exit(1)
    
    user_id = sys.argv[1]
    
    print(f"=== 얼굴 벡터 추출 시작 ===")
    print(f"사용자 ID: {user_id}")
    print(f"이미지 데이터 수신 대기 중 (stdin)...")
    
    try:
        # ---------------------------------------------------------
        # [핵심 변경] 3. stdin에서 바이트 데이터 읽기 및 변환
        # ---------------------------------------------------------
        # Node.js에서 write한 버퍼를 읽어옵니다.
        image_bytes = sys.stdin.buffer.read()
        
        if not image_bytes:
            raise ValueError("이미지 데이터가 비어있습니다.")
            
        print(f"✓ 이미지 데이터 수신 완료 ({len(image_bytes)} bytes)")

        # 바이트 -> PIL Image -> Numpy Array 변환
        # (face_recognition 라이브러리는 보통 numpy array를 입력으로 받습니다)
        image = Image.open(io.BytesIO(image_bytes))
        
        # RGBA(투명도 포함)인 경우 RGB로 변환 (얼굴 인식 오류 방지)
        if image.mode != 'RGB':
            image = image.convert('RGB')
            
        image_array = np.array(image)

        # ---------------------------------------------------------
        # 4. 이미지 배열에서 얼굴 벡터 추출
        # ---------------------------------------------------------
        # 기존: vector = extractor.extract_face_vector(image_path)
        # 변경: 이제 파일 경로가 아니라 '이미지 배열(image_array)'을 넘겨야 합니다.
        vector = extractor.extract_face_vector(image_array)
        
        print(f"✓ 얼굴 벡터 추출 완료 (벡터 크기: {len(vector)})")
        
        # 5. 사용자 ID를 이름으로 벡터 저장
        saved_path = storage.save_vector(user_id, vector, format="pickle")
        print(f"✓ 벡터 저장 완료: {saved_path}")
        
        # 6. 성공 결과 출력
        print("=== 등록 성공 ===")
        return True
        
    except ValueError as e:
        print(f"✗ 오류: {e}")
        return False
    except Exception as e:
        print(f"✗ 예상치 못한 오류: {e}")
        # 디버깅을 위해 에러 상세 내용을 stderr로 출력하면 Node.js에서 볼 수 있습니다.
        sys.stderr.write(str(e))
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)