// pi-client.js - 라즈베리파이에서 실행
const io = require('socket.io-client');

// AWS WAS 주소
const AWS_SERVER = 'http://kmj.shscript.com:8080';

// /sensor namespace로 연결
const socket = io(`${AWS_SERVER}`, {
  transports: ['websocket', 'polling'],
  reconnection: true,
  reconnectionDelay: 1000,
  reconnectionAttempts: Infinity,
});

// 연결 성공
socket.on('connect', () => {
  console.log('✅ AWS 서버 연결 성공:', socket.id);
});

// 연결 끊김
socket.on('disconnect', (reason) => {
  console.warn('❌ AWS 서버 연결 끊김:', reason);
});

// 연결 에러
socket.on('connect_error', (error) => {
  console.error('🔴 연결 에러:', error.message);
});

// AWS로부터 명령 수신 (필요시)
socket.on('command', (data) => {
  console.log('📥 명령 수신:', data);
  // 여기서 센서 제어 등 처리
});

// 센서 데이터 전송 함수
function sendaduData(data) {
  socket.emit('adu-data', data, (response) => {
    console.log('📤 전송 완료:', response);
  });
}

// 예시: 3초마다 센서 데이터 전송
setInterval(() => {
  const aduData = {
  temp: 'temperature',
  humi: 'humidity',
  timestamp: "2025-11-27T...",
  deviceId: 'pi-001'
};
  
  sendaduData(aduData);
}, 3000);

// Ctrl+C로 종료 시 정리
process.on('SIGINT', () => {
  console.log('\n종료 중...');
  socket.disconnect();
  process.exit();
});