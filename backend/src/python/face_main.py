from face_recognition_module import FaceVectorExtractor, VectorStorage, FaceComparator

# 1. 초기 설정
extractor = FaceVectorExtractor(model="hog")
storage = VectorStorage(storage_dir="/home/rlaaudwns/web/backend/src/python/family_faces")
comparator = FaceComparator(tolerance=0.6)

# 2. 가족 사진에서 벡터 추출 및 저장
family_photos = {
    "아버지": "/home/rlaaudwns/web/backend/src/python/photo/dad.jpg",
    "어머니": "/home/rlaaudwns/web/backend/src/python/photo/mom.jpg",
    "형": "/home/rlaaudwns/web/backend/src/python/photo/brother.jpg"
}

print("=== 가족 벡터 저장 ===")
for name, photo_path in family_photos.items():
    try:
        vector = extractor.extract_face_vector(photo_path)
        storage.save_vector(name, vector)
        print(f"✓ {name} 저장 완료")
    except ValueError:
        print(f"✗ {name} 사진에서 얼굴을 찾을 수 없습니다")

# 3. 저장된 벡터 불러오기
print("\n=== 저장된 벡터 확인 ===")
saved_names = storage.list_saved_vectors()
print(f"저장된 사람: {saved_names}")

# 4. 새 사진과 비교
new_photo = "/home/rlaaudwns/web/backend/src/python/photo/unknown5.jpg"
new_vector = extractor.extract_face_vector(new_photo)

print("\n=== 비교 결과 ===")
loaded_vectors = storage.load_multiple_vectors(saved_names)

for name, known_vector in loaded_vectors.items():
    is_match = comparator.compare_faces(known_vector, new_vector)
    distance = comparator.get_face_distance(known_vector, new_vector)
    print(f"{name}: 매칭={is_match}, 거리={distance:.4f}")

# 5. 가장 유사한 가족 찾기
vectors_list = list(loaded_vectors.values())
best_idx, best_distance, is_match = comparator.get_best_match(vectors_list, new_vector)
best_name = saved_names[best_idx]

print(f"\n가장 유사한 가족: {best_name} (거리: {best_distance:.4f})")