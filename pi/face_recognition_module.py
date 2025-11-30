import face_recognition
import numpy as np
import json
import pickle
from pathlib import Path
from typing import List, Tuple, Dict

class FaceVectorExtractor:
    """얼굴 이미지에서 벡터를 추출하는 모듈"""
    
    def __init__(self, model: str = "hog"):
        """
        Args:
            model: 사용할 모델 ("hog" 또는 "cnn")
                  - "hog": CPU에서 빠르게 실행, 정확도 낮음
                  - "cnn": 더 정확하지만 GPU 권장
        """
        self.model = model
    
    def extract_face_vector(self, image_path: str) -> np.ndarray:
        """
        이미지에서 얼굴 벡터를 추출합니다.
        
        Args:
            image_path: 이미지 파일 경로
            
        Returns:
            얼굴 벡터 (128차원 numpy 배열)
            
        Raises:
            ValueError: 얼굴을 찾을 수 없을 때
        """
        image = face_recognition.load_image_file(image_path)
        face_encodings = face_recognition.face_encodings(image, model=self.model)
        
        if not face_encodings:
            raise ValueError(f"이미지에서 얼굴을 찾을 수 없습니다: {image_path}")
        
        # 가장 처음 감지된 얼굴의 벡터 반환
        return face_encodings[0]
    
    def extract_multiple_face_vectors(self, image_path: str) -> List[np.ndarray]:
        """
        이미지에서 여러 개의 얼굴 벡터를 추출합니다.
        
        Args:
            image_path: 이미지 파일 경로
            
        Returns:
            얼굴 벡터 리스트
        """
        image = face_recognition.load_image_file(image_path)
        face_encodings = face_recognition.face_encodings(image, model=self.model)
        
        return face_encodings


class VectorStorage:
    """얼굴 벡터를 저장하고 불러오는 모듈"""
    
    def __init__(self, storage_dir: str = "face_vectors"):
        """
        Args:
            storage_dir: 벡터를 저장할 디렉토리
        """
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
    
    def save_vector(self, name: str, vector: np.ndarray, format: str = "pickle") -> str:
        """
        단일 벡터를 파일로 저장합니다.
        
        Args:
            name: 저장할 이름 (파일명으로 사용)
            vector: 저장할 벡터
            format: 저장 형식 ("pickle" 또는 "json")
            
        Returns:
            저장된 파일 경로
        """
        file_path = self.storage_dir / f"{name}.{format}"
        
        if format == "pickle":
            with open(file_path, "wb") as f:
                pickle.dump(vector, f)
        elif format == "json":
            with open(file_path, "w") as f:
                json.dump(vector.tolist(), f)
        else:
            raise ValueError("형식은 'pickle' 또는 'json'이어야 합니다")
        
        return str(file_path)
    
    def load_vector(self, name: str, format: str = "pickle") -> np.ndarray:
        """
        저장된 벡터를 불러옵니다.
        
        Args:
            name: 저장된 이름
            format: 저장 형식 ("pickle" 또는 "json")
            
        Returns:
            불러온 벡터
        """
        file_path = self.storage_dir / f"{name}.{format}"
        
        if not file_path.exists():
            raise FileNotFoundError(f"파일을 찾을 수 없습니다: {file_path}")
        
        if format == "pickle":
            with open(file_path, "rb") as f:
                vector = pickle.load(f)
        elif format == "json":
            with open(file_path, "r") as f:
                vector = np.array(json.load(f))
        else:
            raise ValueError("형식은 'pickle' 또는 'json'이어야 합니다")
        
        return vector
    
    def save_multiple_vectors(self, vectors_dict: Dict[str, np.ndarray], 
                             format: str = "pickle") -> Dict[str, str]:
        """
        여러 벡터를 한 번에 저장합니다.
        
        Args:
            vectors_dict: {이름: 벡터} 딕셔너리
            format: 저장 형식
            
        Returns:
            {이름: 파일경로} 딕셔너리
        """
        results = {}
        for name, vector in vectors_dict.items():
            file_path = self.save_vector(name, vector, format)
            results[name] = file_path
        return results
    
    def load_multiple_vectors(self, names: List[str], 
                             format: str = "pickle") -> Dict[str, np.ndarray]:
        """
        여러 벡터를 한 번에 불러옵니다.
        
        Args:
            names: 불러올 이름 리스트
            format: 저장 형식
            
        Returns:
            {이름: 벡터} 딕셔너리
        """
        vectors = {}
        for name in names:
            try:
                vectors[name] = self.load_vector(name, format)
            except FileNotFoundError as e:
                print(f"경고: {e}")
        return vectors
    
    def list_saved_vectors(self) -> List[str]:
        """
        저장된 모든 벡터 목록을 반환합니다.
        
        Returns:
            저장된 벡터 이름 리스트
        """
        vectors = []
        for file in self.storage_dir.glob("*"):
            name = file.stem
            vectors.append(name)
        return sorted(vectors)
    
    def delete_vector(self, name: str, format: str = "pickle") -> bool:
        """
        저장된 벡터를 삭제합니다.
        
        Args:
            name: 삭제할 벡터 이름
            format: 저장 형식
            
        Returns:
            삭제 성공 여부
        """
        file_path = self.storage_dir / f"{name}.{format}"
        if file_path.exists():
            file_path.unlink()
            return True
        return False


class FaceComparator:
    """얼굴 벡터를 비교하여 동일인을 감지하는 모듈"""
    
    def __init__(self, tolerance: float = 0.6):
        """
        Args:
            tolerance: 얼굴 비교 허용 오차
                      - 0.6: 기본값 (보통 정확도)
                      - 0.5: 더 엄격함
                      - 0.7: 더 관대함
        """
        self.tolerance = tolerance
    
    def compare_faces(self, known_vector: np.ndarray, 
                      test_vector: np.ndarray) -> bool:
        """
        두 얼굴 벡터를 비교하여 동일인인지 판단합니다.
        
        Args:
            known_vector: 알려진 얼굴 벡터
            test_vector: 비교할 얼굴 벡터
            
        Returns:
            True: 동일인, False: 다른 사람
        """
        result = face_recognition.compare_faces(
            [known_vector], 
            test_vector, 
            tolerance=self.tolerance
        )
        return result[0]
    
    def get_face_distance(self, known_vector: np.ndarray, 
                         test_vector: np.ndarray) -> float:
        """
        두 얼굴 벡터 사이의 거리를 계산합니다.
        (거리가 작을수록 더 유사함)
        
        Args:
            known_vector: 알려진 얼굴 벡터
            test_vector: 비교할 얼굴 벡터
            
        Returns:
            얼굴 거리 (0.0 ~ 1.0)
        """
        distances = face_recognition.face_distance([known_vector], test_vector)
        return distances[0]
    
    def compare_multiple_faces(self, known_vectors: List[np.ndarray], 
                              test_vector: np.ndarray) -> List[bool]:
        """
        여러 개의 알려진 얼굴과 하나의 얼굴을 비교합니다.
        
        Args:
            known_vectors: 알려진 얼굴 벡터 리스트
            test_vector: 비교할 얼굴 벡터
            
        Returns:
            각 비교 결과 리스트
        """
        results = face_recognition.compare_faces(
            known_vectors, 
            test_vector, 
            tolerance=self.tolerance
        )
        return results
    
    def get_best_match(self, known_vectors: List[np.ndarray], 
                       test_vector: np.ndarray) -> Tuple[int, float, bool]:
        """
        가장 유사한 얼굴을 찾습니다.
        
        Args:
            known_vectors: 알려진 얼굴 벡터 리스트
            test_vector: 비교할 얼굴 벡터
            
        Returns:
            (인덱스, 거리, 동일인 여부) 튜플
        """
        distances = face_recognition.face_distance(known_vectors, test_vector)
        min_index = np.argmin(distances)
        min_distance = distances[min_index]
        is_match = min_distance < self.tolerance
        
        return min_index, min_distance, is_match