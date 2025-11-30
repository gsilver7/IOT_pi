import os
import sys
import traceback
from face_recognition_module import FaceVectorExtractor, VectorStorage

def main():
    try:
        print("=== Python 스크립트 시작 ===", flush=True)
        print(f"Python 버전: {sys.version}", flush=True)
        print(f"받은 인자 개수: {len(sys.argv)}", flush=True)
        print(f"전체 인자: {sys.argv}", flush=True)
        
        # 현재 파일이 있는 폴더 경로
        current_dir = os.path.dirname(os.path.abspath(__file__))
        print(f"현재 디렉토리: {current_dir}", flush=True)
        
        # 2. 커맨드라인 인자 처리
        if len(sys.argv) < 3:
            print("❌ 오류: 인자가 부족합니다", flush=True)
            print("사용법: python face_main.py <image_path> <user_id>", flush=True)
            return False
        
        image_path = sys.argv[1]
        user_id = sys.argv[2]
        
        print(f"이미지 경로: {image_path}", flush=True)
        print(f"사용자 ID: {user_id}", flush=True)
        
        # 파일 존재 여부 확인
        if not os.path.exists(image_path):
            print(f"❌ 오류: 파일을 찾을 수 없습니다 -> {image_path}", flush=True)
            return False
        
        print(f"✓ 파일 존재 확인 완료", flush=True)
        
        # 파일 크기 확인
        file_size = os.path.getsize(image_path)
        print(f"✓ 파일 크기: {file_size} bytes", flush=True)
        
        if file_size == 0:
            print(f"❌ 오류: 파일이 비어있습니다", flush=True)
            return False
        
        # 1. 초기 설정
        print("모듈 초기화 시작...", flush=True)
        extractor = FaceVectorExtractor(model="hog")
        print("✓ FaceVectorExtractor 초기화 완료", flush=True)
        
        storage_dir = "/home/rlaaudwns/web/backend/src/python/face_vectors"
        storage = VectorStorage(storage_dir=storage_dir)
        print(f"✓ VectorStorage 초기화 완료 (디렉토리: {storage_dir})", flush=True)
        
        # 3. 얼굴 벡터 추출
        print("얼굴 벡터 추출 시작...", flush=True)
        vector = extractor.extract_face_vector(image_path)
        print(f"✓ 얼굴 벡터 추출 완료 (벡터 크기: {len(vector)})", flush=True)
        
        # 4. 사용자 ID를 이름으로 벡터 저장
        print("벡터 저장 시작...", flush=True)
        saved_path = storage.save_vector(user_id, vector, format="pickle")
        print(f"✓ 벡터 저장 완료: {saved_path}", flush=True)
        
        # 5. 성공 결과 출력
        print("=== 등록 성공 ===", flush=True)
        return True
        
    except ValueError as e:
        print(f"❌ ValueError: {e}", flush=True)
        traceback.print_exc()
        return False
    except ImportError as e:
        print(f"❌ ImportError: {e}", flush=True)
        print("필요한 모듈이 설치되어 있는지 확인하세요", flush=True)
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"❌ 예상치 못한 오류: {type(e).__name__}: {e}", flush=True)
        traceback.print_exc()
        return False

if __name__ == "__main__":
    try:
        success = main()
        exit_code = 0 if success else 1
        print(f"프로그램 종료 (exit code: {exit_code})", flush=True)
        sys.exit(exit_code)
    except Exception as e:
        print(f"❌ 최상위 예외: {e}", flush=True)
        traceback.print_exc()
        sys.exit(1)