// pi-client.js - 라즈베리파이에서 실행

const io = require('socket.io-client');
const { SerialPort } = require('serialport');
const { ReadlineParser } = require('@serialport/parser-readline');
const { spawn } = require('child_process');

const SERIAL_PORT = '/dev/ttyACM0'; // 또는 '/dev/ttyACM0'
const BAUD_RATE = 9600;
const PYTHON_VENV_PATH = '/home/rlaaudwns/web/backend/python/bin/python3'; // 가상환경 경로
const PYTHON_SCRIPT_PATH = '/home/rlaaudwns/web/pi/face_make.py'; // 실행할 스크립트 경로

// 시리얼 포트 초기화
const port = new SerialPort({
  path: SERIAL_PORT,
  baudRate: BAUD_RATE,
}); 

const parser = port.pipe(new ReadlineParser({ delimiter: '\n' }));

// AWS WAS 주소
const AWS_SERVER = 'https://kmj.shscript.com';

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

socket.on('python', (data) => {
  console.log('🐍 Python 스크립트 실행 요청:', data);

  const scriptPath = data.scriptPath || PYTHON_SCRIPT_PATH;
  const venvPath = data.venvPath || PYTHON_VENV_PATH;
  const userId = data.userId || 'unknown'; // 유저 ID (파일명이나 인자로 사용)

  // 1. 이미지 데이터 처리
  if (!data.image) {
    console.error('❌ 이미지가 없습니다.');
    return;
  }

  try {
    // Base64 헤더 제거 및 버퍼 변환
    const base64Data = data.image.replace(/^data:image\/\w+;base64,/, "");
    const imgBuffer = Buffer.from(base64Data, 'base64');

    // 2. 파일 저장 경로 설정 (현재 폴더에 저장)
    // 파일명 중복 방지를 위해 timestamp 사용 (예: face_1701234567890.jpg)
    const fileName = `face_${Date.now()}.jpg`; 
    const filePath = path.join(__dirname, fileName); // 현재 실행 위치에 저장

    console.log(`💾 이미지 저장 시작: ${filePath}`);

    // 3. 파일 저장 (비동기)
    fs.writeFile(filePath, imgBuffer, (err) => {
      if (err) {
        console.error('❌ 이미지 저장 실패:', err);
        socket.emit('python-result', { success: false, error: 'Image save failed' });
        return;
      }

      console.log('✅ 이미지 저장 완료. Python 실행 시작...');

      // ---------------------------------------------------------
      // [핵심] 4. 저장이 완료되면 Python 실행
      // ---------------------------------------------------------
      // 인자로 [스크립트경로, 이미지경로, 유저ID] 를 넘깁니다.
      const args = [scriptPath, filePath, userId]; 
      
      const pythonProcess = spawn(venvPath, args);

      let resultBuffer = '';
      let errorBuffer = '';

      // 표준 출력 수신
      pythonProcess.stdout.on('data', (output) => {
        resultBuffer += output.toString();
      });

      // 에러 출력 수신
      pythonProcess.stderr.on('data', (error) => {
        errorBuffer += error.toString();
      });

      // 프로세스 종료 처리
      pythonProcess.on('close', (code) => {
        console.log(`🐍 Python 프로세스 종료 (코드: ${code})`);

        // (선택사항) 파이썬 처리가 끝났으니 이미지를 삭제할까요?
        // fs.unlink(filePath, () => console.log('🗑️ 임시 이미지 삭제 완료'));

        if (code === 0) {
          console.log('🐍 Python 최종 출력:', resultBuffer);
          socket.emit('python-result', {
            deviceId: 'pi-001',
            success: true,
            output: resultBuffer.trim(),
            timestamp: new Date().toISOString()
          });
        } else {
          console.error('🔴 Python 에러:', errorBuffer);
          socket.emit('python-result', {
            deviceId: 'pi-001',
            success: false,
            error: errorBuffer,
            timestamp: new Date().toISOString()
          });
        }
      });

      pythonProcess.on('error', (err) => {
        console.error('🔴 Python 실행 에러:', err.message);
        socket.emit('python-result', { success: false, error: err.message });
      });

    }); // end of fs.writeFile

  } catch (e) {
    console.error('이미지 처리 중 예외 발생:', e);
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
let latestAduData = { temp: 0, humi: 0, co2: 0, light: 0};

// 아두이노로부터 데이터 수신
parser.on('data', (data) => {
  console.log('📥 아두이노 데이터:', data);
    
  try {
    // JSON 형식으로 받는 경우
    const aduData = JSON.parse(data);
    aduData.timestamp = new Date().toISOString();
    aduData.deviceId = 'pi-001';
    
    latestAduData = { temp: aduData.temp, humi: aduData.humi, co2: aduData.co2, light: aduData.light};
    sendaduData(aduData);
  } catch (e) {
    // 일반 텍스트로 받는 경우 (예: "25.5,60.2")
    const values = data.trim().split(',');
    if (values.length >= 2) {
      const aduData = {
        temp: parseFloat(values[0]),
        humi: parseFloat(values[1]),
        co2: parseFloat(values[2]),
        light: parseFloat(values[3]),
        timestamp: new Date().toISOString(),
        deviceId: 'pi-001'
      };
      
      latestAduData = { temp: aduData.temp, humi: aduData.humi, co2: aduData.co2, light: aduData.light};
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
    co2: latestAduData.co2,
    light: latestAduData.light,
    timestamp: new Date().toISOString(),
    deviceId: 'pi-001'
  };
  
  sendaduData(aduData);
}, 3000);

// 🆕 프론트엔드로부터 제어 명령 수신
socket.on('control', (data) => {
  console.log('📥 제어 명령 수신:', data);
  
  // JSON을 문자열로 변환하여 아두이노로 전송
  const jsonString = JSON.stringify(data);
  port.write(jsonString + '\n');
  
  console.log('📤 아두이노로 전송:', jsonString);
  console.log(data);
});

let ffmpegProcess = null;

function startWebcamStreaming() {
  if (ffmpegProcess) {
    console.log('⚠️ 이미 스트리밍 중');
    return;
  }
  
  console.log('📹 웹캠 스트리밍 시작 시도...');
  console.log('📹 소켓 연결:', socket.connected);
  
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
  let frameCount = 0;

  ffmpegProcess.stdout.on('data', (data) => {
    frameCount++;
    
    frameBuffer = Buffer.concat([frameBuffer, data]);

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

      frameBuffer = frameBuffer.slice(end + 2);
      start = frameBuffer.indexOf(Buffer.from([0xFF, 0xD8]));
      end = frameBuffer.indexOf(Buffer.from([0xFF, 0xD9]));
    }
  });

  // 🆕 stderr 로그 활성화 (중요!)
  ffmpegProcess.stderr.on('data', (data) => {
    console.log('📹 ffmpeg 로그:', data.toString());
  });

  ffmpegProcess.on('close', (code) => {
    console.log('📹 웹캠 스트리밍 종료:', code);
    ffmpegProcess = null;
  });

  ffmpegProcess.on('error', (error) => {
    console.error('🔴 ffmpeg 실행 에러:', error.message);
    ffmpegProcess = null;
  });
  
  // 🆕 프로세스 시작 확인
  console.log('📹 ffmpeg 프로세스 시작됨, PID:', ffmpegProcess.pid);
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