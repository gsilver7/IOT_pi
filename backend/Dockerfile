FROM node:20

# 2. 시스템 패키지 설치 (Debian/Ubuntu 명령어 사용)
# Alpine 패키지 이름들을 Debian용으로 번역했습니다.
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    make \
    g++ \
    build-essential \
    cmake \
    libcairo2-dev \
    libjpeg-dev \
    libpango1.0-dev \
    libgif-dev \
    libpixman-1-dev \
    libusb-1.0-0-dev \
    libopenblas-dev \
    liblapack-dev \
    libx11-dev \
    libgtk-3-dev \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 4. [중요] PIP 타임아웃 방지 설정 (환경변수)
ENV PIP_DEFAULT_TIMEOUT=1000

COPY requirements.txt ./
RUN pip install --no-cache-dir --default-timeout=1000 -r requirements.txt

# package.json과 package-lock.json 복사
COPY package*.json ./

# 의존성 설치
RUN npm config set fetch-timeout 600000 && \
    npm config set fetch-retries 5 && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 120000 && \
    npm ci

# 소스 코드 복사
COPY . .

# NestJS 빌드
RUN npm run build

# 포트 노출 (NestJS 기본 포트는 3000)
EXPOSE 4000

# 프로덕션 모드로 실행
CMD ["npm", "run", "start:prod"]
