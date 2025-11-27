FROM node:20-alpine

RUN apk add --no-cache \
    make \
    g++ \
    cairo-dev \
    jpeg-dev \
    pango-dev \
    giflib-dev \
    eudev-dev

WORKDIR /app

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
