// pi-client.js - 라즈베리파이에서 실행

const io = require('socket.io-client');
const { SerialPort } = require('serialport');
const { ReadlineParser } = require('@serialport/parser-readline');
const { spawn } = require('child_process');

const SERIAL_PORT = '/dev/ttyACM0'; // 또는 '/dev/ttyACM0'
const BAUD_RATE = 9600;

// 시리얼 포트 초기화
const port = new SerialPort({
  path: SERIAL_PORT,
  baudRate: BAUD_RATE,
}); 

const parser = port.pipe(new ReadlineParser({ delimiter: '\n' }));

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
  startWebcamStreaming();
});

// 연결 끊김
socket.on('disconnect', (reason) => {
  console.warn('❌ AWS 서버 연결 끊김:', reason);
  stopWebcamStreaming();
});

// 연결 에러
socket.on('connect_error', (error) => {
  console.error('🔴 연결 에러:', error.message);
});

// AWS로부터 명령 수신 (필요시)
socket.on('command', (data) => {
  console.log('📥 명령 수신:', data);
  
  if (data.command === 'stop-webcam') {
    stopWebcamStreaming();
  }
  
  if (data.command) {
    port.write(data.command + '\n');
  }
});

// 시리얼 포트 연결 성공
port.on('open', () => {
  console.log('✅ 아두이노 시리얼 포트 연결:', SERIAL_PORT);
});

// 시리얼 포트 에러
port.on('error', (err) => {
  console.error('🔴 시리얼 포트 에러:', err.message);
});

// 센서 데이터 저장 변수
let latestAduData = { temp: 0, humi: 0 };

// 아두이노로부터 데이터 수신
parser.on('data', (data) => {
  console.log('📥 아두이노 데이터:', data);
    
  try {
    // JSON 형식으로 받는 경우
    const aduData = JSON.parse(data);
    aduData.timestamp = new Date().toISOString();
    aduData.deviceId = 'pi-001';
    
    latestAduData = { temp: aduData.temp, humi: aduData.humi };
    sendaduData(aduData);
  } catch (e) {
    // 일반 텍스트로 받는 경우 (예: "25.5,60.2")
    const values = data.trim().split(',');
    if (values.length >= 2) {
      const aduData = {
        temp: parseFloat(values[0]),
        humi: parseFloat(values[1]),
        timestamp: new Date().toISOString(),
        deviceId: 'pi-001'
      };
      
      latestAduData = { temp: aduData.temp, humi: aduData.humi };
      sendaduData(aduData);
    }
  }
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
    temp: latestAduData.temp,
    humi: latestAduData.humi,
    timestamp: new Date().toISOString(),
    deviceId: 'pi-001'
  };
  
  sendaduData(aduData);
}, 3000);

let ffmpegProcess = null;

function startWebcamStreaming() {
  if (ffmpegProcess) return;
  
  console.log('📹 웹캠 스트리밍 시작...');
  
  // ffmpeg로 웹캠 캡처
  ffmpegProcess = spawn('ffmpeg', [
    '-f', 'v4l2',
    '-framerate', '15',
    '-video_size', '640x480',
    '-i', '/dev/video0',
    '-f', 'mjpeg',
    '-q:v', '5',
    '-'
  ]);

  let frameBuffer = Buffer.alloc(0);

  ffmpegProcess.stdout.on('data', (data) => {
    frameBuffer = Buffer.concat([frameBuffer, data]);

    // JPEG 시작(0xFFD8)과 끝(0xFFD9) 마커 찾기
    let start = frameBuffer.indexOf(Buffer.from([0xFF, 0xD8]));
    let end = frameBuffer.indexOf(Buffer.from([0xFF, 0xD9]));

    while (start !== -1 && end !== -1 && end > start) {
      const frame = frameBuffer.slice(start, end + 2);
      
      // AWS로 프레임 전송
      socket.emit('webcam-frame', {
        deviceId: 'pi-001',
        frame: frame.toString('base64'),
        timestamp: new Date().toISOString()
      });

      // 버퍼에서 전송된 프레임 제거
      frameBuffer = frameBuffer.slice(end + 2);
      start = frameBuffer.indexOf(Buffer.from([0xFF, 0xD8]));
      end = frameBuffer.indexOf(Buffer.from([0xFF, 0xD9]));
    }
  });

  ffmpegProcess.stderr.on('data', (data) => {
    // ffmpeg 로그 (필요시 주석 해제)
    // console.error('ffmpeg:', data.toString());
  });

  ffmpegProcess.on('close', (code) => {
    console.log('📹 웹캠 스트리밍 종료:', code);
    ffmpegProcess = null;
  });

  ffmpegProcess.on('error', (error) => {
    console.error('🔴 ffmpeg 에러:', error.message);
  });
}

function stopWebcamStreaming() {
  if (ffmpegProcess) {
    console.log('📹 웹캠 스트리밍 중지...');
    ffmpegProcess.kill('SIGTERM');
    ffmpegProcess = null;
  }
}

// Ctrl+C로 종료 시 정리
process.on('SIGINT', () => {
  console.log('\n종료 중...');
  stopWebcamStreaming();
  port.close();
  socket.disconnect();
  process.exit();
});