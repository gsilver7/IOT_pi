# 파이썬 파일을 가상환경에서 돌려주는 코드
# 가상환경을 쓰는 이유는 linux환경에서 
# pip을 사용하기 어렵기 때문
# 이거 안하면 매번 가상환경 껐다켜야됨

import subprocess

# 가상 환경의 파이썬 인터프리터 경로
python_executable = "../../python/bin/python"

# 실행할 파이썬 스크립트
script_to_run = "opencv.py"

# subprocess.run()을 사용하여 스크립트 실행
subprocess.run([python_executable, script_to_run])
