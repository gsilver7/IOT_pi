import os
import sys
import traceback
import pickle
import json
import numpy as np

# 기존 모듈 임포트 (같은 폴더에 face_recognition_module.py가 있어야 함)
try:
    from face_recognition_module import FaceVectorExtractor, FaceComparator
except ImportError as e:
    print(f"❌ 모듈 임포트 오류: {e}", flush=True)
    sys.exit(1)

def load_vector_direct(path):
    """경로에서 직접 피클 파일을 로드하는 헬퍼 함수"""
    with open(path, 'rb') as f:
        return pickle.load(f)

def main():
    try:
        print("=== 얼굴 비교(인증) 스크립트 시작 ===", flush=True)
        print(f"Python 버전: {sys.version}", flush=True)
        print(f"받은 인자 개수: {len(sys.argv)}", flush=True)
        print(f"전체 인자: {sys.argv}", flush=True)
        
        # 현재 파일이 있는 폴더 경로
        current_dir = os.path.dirname(os.path.abspath(__file__))
        print(f"현재 디렉토리: {current_dir}", flush=True)
        
        # 2. 커맨드라인 인자 처리
        # argv[1]: 저장된 벡터 파일 경로 (.pkl)
        # argv[2]: 비교할 새로운 이미지 경로 (.jpg/png)
        if len(sys.argv) < 3:
            print("❌ 오류: 인자가 부족합니다", flush=True)
            print("사용법: python face_compare.py <vector_path> <image_path>", flush=True)
            return False
        
        vector_path = sys.argv[1]
        image_path = sys.argv[2]
        
        print(f"기준 벡터 경로: {vector_path}", flush=True)
        print(f"비교 이미지 경로: {image_path}", flush=True)
        
        # 3. 파일 존재 여부 확인
        if not os.path.exists(vector_path):
            print(f"❌ 오류: 벡터 파일을 찾을 수 없습니다 -> {vector_path}", flush=True)
            return False
        
        if not os.path.exists(image_path):
            print(f"❌ 오류: 이미지 파일을 찾을 수 없습니다 -> {image_path}", flush=True)
            return False
            
        print(f"✓ 파일 존재 확인 완료", flush=True)
        
        # 4. 모듈 초기화
        print("모듈 초기화 시작...", flush=True)
        extractor = FaceVectorExtractor(model="hog")
        # tolerance: 낮을수록 엄격함 (0.4~0.5 권장 for security)
        comparator = FaceComparator(tolerance=0.5) 
        print("✓ FaceVectorExtractor 및 FaceComparator 초기화 완료", flush=True)
        
        # 5. 저장된 벡터 로드 (Reference)
        print("저장된 벡터 로드 중...", flush=True)
        try:
            known_vector = load_vector_direct(vector_path)
            print(f"✓ 벡터 로드 완료 (데이터 타입: {type(known_vector)})", flush=True)
        except Exception as e:
            print(f"❌ 벡터 파일 로드 실패: {e}", flush=True)
            return False

        # 6. 새 이미지에서 벡터 추출 (Test)
        print("새 이미지에서 얼굴 벡터 추출 중...", flush=True)
        try:
            new_vector = extractor.extract_face_vector(image_path)
            print(f"✓ 새 얼굴 벡터 추출 완료 (크기: {len(new_vector)})", flush=True)
        except ValueError as e:
            print(f"❌ 얼굴 감지 실패: {e}", flush=True)
            # 얼굴을 못 찾은 경우 결과 전송 (match: false)
            result = {
                "success": False,
                "match": False,
                "message": "얼굴을 찾을 수 없습니다."
            }
            print("=== COMPARE RESULT ===", flush=True)
            print(json.dumps(result), flush=True)
            return False

        # 7. 두 벡터 비교
        print("벡터 비교 수행 중...", flush=True)
        is_match = comparator.compare_faces(known_vector, new_vector)
        distance = comparator.get_face_distance(known_vector, new_vector)
        
        print(f"✓ 비교 완료 | 거리(Distance): {distance:.4f} | 기준: {comparator.tolerance}", flush=True)
        
        # 8. 최종 결과 JSON 출력
        # Node.js가 파싱하기 쉽도록 JSON 구조로 출력합니다.
        result = {
            "success": True,
            "match": bool(is_match),      # True 또는 False
            "distance": float(distance),
            "message": "인증 성공" if is_match else "불일치"
        }
        
        print("=== COMPARE RESULT ===", flush=True)
        print(json.dumps(result), flush=True)
        
        if is_match:
            print("=== 인증 성공 (MATCH) ===", flush=True)
        else:
            print("=== 인증 실패 (NO MATCH) ===", flush=True)
            
        return True
        
    except Exception as e:
        print(f"❌ 예상치 못한 오류: {type(e).__name__}: {e}", flush=True)
        traceback.print_exc()
        return False

if __name__ == "__main__":
    try:
        success = main()
        # 스크립트 실행 자체의 성공/실패 여부 (비교 결과와는 다름)
        exit_code = 0 if success else 1
        print(f"프로그램 종료 (exit code: {exit_code})", flush=True)
        sys.exit(exit_code)
    except Exception as e:
        print(f"❌ 최상위 예외: {e}", flush=True)
        traceback.print_exc()
        sys.exit(1)