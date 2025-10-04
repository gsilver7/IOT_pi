import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // ✅ 여기에 원하는 호스트 주소를 설정합니다.
    host: '0.0.0.0', // 모든 네트워크 인터페이스에서 접근 가능하게 합니다.
    // host: '192.168.1.10', // 특정 내부 IP 주소로 설정
    
    // 포트를 바꾸려면 아래와 같이 port 속성을 추가합니다.
    port: 3000, 
    allowedHosts: [
      'kmj-pi.local',
    ],
  },
});