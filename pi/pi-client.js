// pi-client.js - 라즈베리파이에서 실행

const io = require('socket.io-client');
const path = require('path');
const fs = require('fs');
const { SerialPort } = require('serialport');
const { ReadlineParser } = require('@serialport/parser-readline');
const { spawn } = require('child_process');

// const { initUnifiedBluetoothScanner, 
//   stopUnifiedBluetoothScanner  } = require('./ble-scanner'); // 이 줄 확인



const SERIAL_PORT = '/dev/ttyACM0'; // 또는 '/dev/ttyACM0'

const PYTHON_VENV_PATH = '/home/rlaaudwns/web/backend/python/bin/python3'; // 가상환경 경로
const PYTHON_SCRIPT_PATH = '/home/rlaaudwns/web/pi/face_make.py'; // 실행할 스크립트 경로

// 시리얼 포트 초기화
const portA = new SerialPort({ path: '/dev/ttyACM0', baudRate: 9600 }); 
const portB = new SerialPort({ path: '/dev/ttyACM1', baudRate: 9600 });

const parserA = portA.pipe(new ReadlineParser({ delimiter: '\n' }));


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
    // initUnifiedBluetoothScanner(socket);
});

// 연결 끊김
socket.on('disconnect', (reason) => {
  console.warn('❌ AWS 서버 연결 끊김:', reason);
  stopWebcamStreaming();
  // stopUnifiedBluetoothScanner();
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
  const userId = data.userId || 'unknown';

  // 1. 이미지 데이터 처리
  if (!data.image) {
    console.error('❌ 이미지가 없습니다.');
    socket.emit('python-result', { success: false, error: 'No image data' });
    return;
  }

  try {
    // Base64 헤더 제거 및 버퍼 변환
    const base64Data = data.image.replace(/^data:image\/\w+;base64,/, "");
    const imgBuffer = Buffer.from(base64Data, 'base64');

    console.log(`📊 이미지 버퍼 크기: ${imgBuffer.length} bytes`);

    // 2. 파일 저장 경로 설정
    const fileName = `face_${userId}_${Date.now()}.jpg`; 
    const filePath = path.join(__dirname, fileName);

    console.log(`💾 이미지 저장 시작: ${filePath}`);

    // 3. 파일 저장 (비동기)
    fs.writeFile(filePath, imgBuffer, (err) => {
      if (err) {
        console.error('❌ 이미지 저장 실패:', err);
        socket.emit('python-result', { success: false, error: 'Image save failed' });
        return;
      }

      // 저장된 파일 크기 확인
      const stats = fs.statSync(filePath);
      console.log(`✅ 이미지 저장 완료 (크기: ${stats.size} bytes)`);

      // 4. Python 실행
      const args = ['-u', scriptPath, filePath, userId]; 
      console.log(`🐍 Python 실행: ${venvPath} ${args.join(' ')}`);
      
      const pythonProcess = spawn(venvPath, args);

      let resultBuffer = '';
      let errorBuffer = '';

      // 표준 출력 수신
      pythonProcess.stdout.on('data', (output) => {
        const text = output.toString();
        console.log(`[Python stdout] ${text}`);
        resultBuffer += text;
      });

      // 에러 출력 수신
      pythonProcess.stderr.on('data', (error) => {
        const text = error.toString();
        console.error(`[Python stderr] ${text}`);
        errorBuffer += text;
      });

      // 프로세스 종료 처리
      pythonProcess.on('close', (code) => {
        console.log(`🐍 Python 프로세스 종료 (코드: ${code})`);
        console.log(`📝 전체 출력 길이: ${resultBuffer.length} chars`);
        console.log(`📝 전체 에러 길이: ${errorBuffer.length} chars`);

        // 임시 이미지 삭제
        fs.unlink(filePath, (unlinkErr) => {
          if (unlinkErr) {
            console.error('🗑️ 임시 이미지 삭제 실패:', unlinkErr);
          } else {
            console.log('🗑️ 임시 이미지 삭제 완료');
          }
        });

        if (code === 0) {
          console.log('✅ Python 실행 성공');

          // ----------------------------------------------------------------
          // [추가된 로직] 로그에서 벡터 저장 경로 추출하기
          // ----------------------------------------------------------------
          let vectorPath = null;
          
          // 파이썬 로그 예시: "✓ 벡터 저장 완료: /home/.../face_vectors/user123.pkl"
          // 정규식으로 "벡터 저장 완료:" 뒤에 있는 경로 부분을 잡아냅니다.
          const match = resultBuffer.match(/벡터 저장 완료:\s*(.+)/);

          if (match && match[1]) {
            vectorPath = match[1].trim(); // 로그에서 추출한 실제 경로
          } else {
            // 만약 로그 파싱에 실패했다면, 요청받은 기본 경로와 ID로 추정치를 넣습니다.
            // (파이썬 쪽 저장 로직이 .pkl 이라고 가정)
            vectorPath = `/home/rlaaudwns/web/backend/src/python/face_vectors/${userId}.pkl`;
          }

          console.log(`📍 추출된 벡터 경로: ${vectorPath}`);

          // 결과 전송
          socket.emit('python-result', {
            deviceId: 'pi-001',
            success: true,
            userId: userId,
            output: resultBuffer.trim(),
            vector: vectorPath, // 👈 여기에 벡터 경로 추가됨!
            timestamp: new Date().toISOString()
          });
          console.log("전송 잘됨");
        } else {
          console.error('❌ Python 실행 실패 (종료 코드:', code, ')');
          socket.emit('python-result', {
            deviceId: 'pi-001',
            success: false,
            error: errorBuffer || `Process exited with code ${code}`,
            timestamp: new Date().toISOString()
          });
        }
      });

      pythonProcess.on('error', (err) => {
        console.error('🔴 Python 프로세스 실행 에러:', err);
        socket.emit('python-result', { success: false, error: err.message });
      });

    }); // end of fs.writeFile

  } catch (e) {
    console.error('❌ 이미지 처리 중 예외 발생:', e);
    socket.emit('python-result', { success: false, error: e.message });
  }
});

socket.on('compare', (data) => {
  console.log('🔍 얼굴 비교 요청 수신:', data);

  // 1. 필요한 데이터 추출
  // data 구조: { id, face, image }
  const storedVectorPath = data.face; // DB에 저장된 벡터 파일 경로
  const inputImageBase64 = data.image; // 지금 찍은 얼굴 이미지
  const userId = data.id || 'unknown';

  // 스크립트 경로 (face_compare.py가 있는 위치)
  // PYTHON_SCRIPT_PATH가 있는 폴더와 같다고 가정합니다.
  const compareScriptPath = path.join(path.dirname(PYTHON_SCRIPT_PATH), 'face_compare.py');
  const venvPath = PYTHON_VENV_PATH;

  if (!inputImageBase64 || !storedVectorPath) {
    console.error('❌ 비교할 데이터가 부족합니다.');
    socket.emit('compare-result', { success: false, error: 'Missing data' });
    return;
  }

  try {
    // 2. 입력 이미지 파일로 저장 (비교용)
    const base64Data = inputImageBase64.replace(/^data:image\/\w+;base64,/, "");
    const imgBuffer = Buffer.from(base64Data, 'base64');
    
    // 임시 파일명: compare_userid_timestamp.jpg
    const tempFileName = `compare_${userId}_${Date.now()}.jpg`;
    const tempFilePath = path.join(__dirname, tempFileName);

    console.log(`💾 비교용 이미지 저장: ${tempFilePath}`);

    fs.writeFile(tempFilePath, imgBuffer, (err) => {
      if (err) {
        console.error('❌ 이미지 저장 실패:', err);
        socket.emit('compare-result', { success: false, error: 'Image save failed' });
        return;
      }

      console.log('✅ 이미지 저장 완료. 비교 스크립트 실행...');

      // ---------------------------------------------------------
      // 3. Python 실행 (face_compare.py)
      // ---------------------------------------------------------
      // 인자 순서: [스크립트, 벡터경로, 이미지경로]
      // 파이썬: sys.argv[1]=vector_path, sys.argv[2]=image_path
      const args = ['-u', compareScriptPath, storedVectorPath, tempFilePath];
      
      console.log(`🐍 Python 실행: ${venvPath} ${args.join(' ')}`);
      
      const pythonProcess = spawn(venvPath, args);

      let resultBuffer = '';
      let errorBuffer = '';

      pythonProcess.stdout.on('data', (output) => {
        const text = output.toString();
        // console.log(`[Python] ${text}`); // 로그가 너무 많으면 주석 처리
        resultBuffer += text;
      });

      pythonProcess.stderr.on('data', (error) => {
        errorBuffer += error.toString();
      });

      pythonProcess.on('close', (code) => {
        console.log(`🐍 비교 프로세스 종료 (코드: ${code})`);

        // 임시 이미지 삭제
        fs.unlink(tempFilePath, () => console.log('🗑️ 임시 이미지 삭제 완료'));

        if (code === 0) {
          // 4. 결과 파싱 (JSON)
          let comparisonResult = { success: false, match: false };
          
          try {
            // 파이썬 로그가 섞여있을 수 있으므로 "=== COMPARE RESULT ===" 다음 줄을 찾거나
            // JSON 형태인 줄을 찾아서 파싱해야 합니다.
            
            // 방법 A: "=== COMPARE RESULT ===" 키워드 활용
            const lines = resultBuffer.split('\n');
            const targetIndex = lines.findIndex(line => line.includes("=== COMPARE RESULT ==="));
            
            if (targetIndex !== -1 && lines[targetIndex + 1]) {
                comparisonResult = JSON.parse(lines[targetIndex + 1]);
            } else {
                // 방법 B: 전체 텍스트에서 JSON 객체 찾기 (Fallback)
                // { "success": true ... } 형태의 문자열을 정규식으로 찾음
                const jsonMatch = resultBuffer.match(/\{.*"match":.*\}/);
                if (jsonMatch) {
                    comparisonResult = JSON.parse(jsonMatch[0]);
                }
            }
            
            console.log('📊 최종 비교 결과:', comparisonResult);

            // 5. 결과에 따라 동작 수행
            if (comparisonResult.success && comparisonResult.match) {
                console.log('🔓 [인증 성공] 문을 엽니다!');
                
                // 백엔드(NestJS)로 결과 전송
                socket.emit('compare-result', { 
                    success: true, 
                    match: true, 
                    userId: userId,
                    distance: comparisonResult.distance 
                });
                
                // (선택) 아두이노 문 열기 명령 등 추가 가능
                // serialPort.write('OPEN_DOOR'); 

            } else {
                console.log('🔒 [인증 실패] 얼굴이 일치하지 않습니다.');
                socket.emit('compare-result', { 
                    success: true, 
                    match: false, 
                    message: '얼굴 불일치' 
                });
            }

          } catch (e) {
            console.error('❌ JSON 파싱 에러:', e);
            console.error('원본 출력:', resultBuffer);
            socket.emit('compare-result', { success: false, error: 'Result parsing failed' });
          }

        } else {
          // ---------------------------------------------------------
          // [수정] 실패 시 원인 분석 로직 강화
          // ---------------------------------------------------------
          console.error('❌ Python 실행 실패 (종료 코드:', code, ')');
          
          // 1. stderr가 비어있다면 stdout(resultBuffer)에 에러 내용이 있는지 확인
          const errorMsg = errorBuffer || resultBuffer || '알 수 없는 에러';
          
          console.error('🔴 상세 에러 내용:', errorMsg); // 👈 이걸 봐야 원인을 알 수 있습니다!

          socket.emit('compare-result', { 
            success: false, 
            error: errorMsg 
          });
        }
      });
    });

  } catch (e) {
    console.error('비교 처리 중 예외:', e);
  }
});

// 시리얼 포트 연결 성공
portA.on('open', () => {
  console.log('✅ 아두이노 시리얼 포트 연결:', SERIAL_PORT);
});

// 시리얼 포트 에러
portA.on('error', (err) => {
  console.error('🔴 시리얼 포트 에러:', err.message);
});

// 센서 데이터 저장 변수
let latestAduData = { temp: 0, humi: 0, co2: 0, light: 0};

// 아두이노로부터 데이터 수신
parserA.on('data', (data) => {
    
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
  portA.write(jsonString + '\n');
  portB.write(jsonString + '\n');
  
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
  // stopUnifiedBluetoothScanner();
  portA.close();
  portB.close();
  socket.disconnect();
  process.exit();
});

