FROM node:20-alpine

WORKDIR /app

# package.json과 package-lock.json 복사
COPY package*.json ./

# 의존성 설치
RUN npm ci

# 소스 코드 복사
COPY . .

# NestJS 빌드
RUN npm run build

# 포트 노출 (NestJS 기본 포트는 3000)
EXPOSE 3000

# 프로덕션 모드로 실행
CMD ["npm", "run", "start:prod"]
