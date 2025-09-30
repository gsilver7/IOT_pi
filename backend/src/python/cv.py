# face_detect.py

import sys
import os

def main():
    import numpy
    import cv2
    import face_recognition  # 💥 이걸 main() 안에 넣으세요
    print("numpy 버전:", numpy.__version__)
    print("face_recognition import 성공")

if __name__ == "__main__":
    print("[DEBUG] __name__ == '__main__'")
    main()
