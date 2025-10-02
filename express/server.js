// server.js - Socket.IO 웹캠 스트리밍 서버
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const ffmpeg = require('fluent-ffmpeg');

const app = express();
app.use(cors());
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
  maxHttpBufferSize: 1e8 // 100MB 버퍼 크기
});

const PORT = 4000;

// 연결된 클라이언트 관리
let connectedClients = new Set();
let streamCommand = null;
let isStreaming = false;

// 정적 파일 제공
app.use(express.static('public'));

// FFmpeg 스트림 시작 함수
function startWebcamStream() {
  if (isStreaming) {
    console.log('Stream already running');
    return;
  }

  console.log('Starting webcam stream...');
  isStreaming = true;

  streamCommand = ffmpeg('/dev/video0')
    .inputOptions(['-re', '-f', 'v4l2'])
    .size('640x480')
    .fps(15)
    .videoCodec('mjpeg')
    .outputOptions([
      '-f', 'image2pipe',
      '-vcodec', 'mjpeg',
      '-q:v', '5',
      '-huffman', 'optimal'
    ]);

  streamCommand
    .on('start', (cmdline) => {
      console.log('FFmpeg started:', cmdline);
    })
    .on('error', (err) => {
      console.error('FFmpeg error:', err.message);
      stopWebcamStream();
    })
    .on('end', () => {
      console.log('FFmpeg stream ended');
      stopWebcamStream();
    });

  const stream = streamCommand.pipe();
  let buffer = Buffer.alloc(0);
  let frameCount = 0;

  stream.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);

    // JPEG 시작(FFD8)과 끝(FFD9) 마커 찾기
    let startIdx = buffer.indexOf(Buffer.from([0xFF, 0xD8]));
    let endIdx = buffer.indexOf(Buffer.from([0xFF, 0xD9]));

    while (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
      // 완전한 JPEG 프레임 추출
      const frame = buffer.slice(startIdx, endIdx + 2);
      buffer = buffer.slice(endIdx + 2);

      frameCount++;
      
      // 모든 연결된 클라이언트에게 프레임 전송
      if (connectedClients.size > 0) {
        const base64Frame = frame.toString('base64');
        io.emit('frame', {
          data: base64Frame,
          timestamp: Date.now(),
          frameNumber: frameCount
        });

        if (frameCount % 100 === 0) {
          console.log(`Streamed ${frameCount} frames to ${connectedClients.size} client(s)`);
        }
      }

      // 다음 프레임 찾기
      startIdx = buffer.indexOf(Buffer.from([0xFF, 0xD8]));
      endIdx = buffer.indexOf(Buffer.from([0xFF, 0xD9]));
    }
  });

  stream.on('error', (err) => {
    console.error('Stream error:', err.message);
    stopWebcamStream();
  });
}

// FFmpeg 스트림 중지 함수
function stopWebcamStream() {
  if (streamCommand) {
    console.log('Stopping webcam stream...');
    streamCommand.kill('SIGKILL');
    streamCommand = null;
  }
  isStreaming = false;
}

// Socket.IO 연결 처리
io.on('connection', (socket) => {
  console.log(`✅ Client connected: ${socket.id}`);
  connectedClients.add(socket.id);
  
  // 첫 클라이언트 연결 시 스트림 시작
  if (connectedClients.size === 1) {
    startWebcamStream();
  }

  // 클라이언트에게 연결 확인 전송
  socket.emit('connected', {
    message: 'Connected to webcam stream',
    clientId: socket.id,
    timestamp: Date.now()
  });

  // 클라이언트 연결 해제 처리
  socket.on('disconnect', () => {
    console.log(`❌ Client disconnected: ${socket.id}`);
    connectedClients.delete(socket.id);
    
    // 모든 클라이언트 연결 해제 시 스트림 중지
    if (connectedClients.size === 0) {
      console.log('No clients connected. Stopping stream...');
      stopWebcamStream();
    }
  });

  // 에러 처리
  socket.on('error', (error) => {
    console.error(`Socket error for ${socket.id}:`, error.message);
    connectedClients.delete(socket.id);
  });
});

// 테스트용 HTML 페이지
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<body>
    <div class="container">
        <canvas id="streamCanvas" width="640" height="480"></canvas>
    </div>
    
    <script src="/socket.io/socket.io.js"></script>
    <script>
        const canvas = document.getElementById('streamCanvas');
        const ctx = canvas.getContext('2d');
        let socket;
        
        function connect() {
            // 서버에 소켓 연결을 시도합니다.
            socket = io('/', {
                transports: ['websocket', 'polling']
            });
            
            // 'connect' 이벤트: 서버에 성공적으로 연결되었을 때
            socket.on('connect', () => {
                console.log('서버에 연결되었습니다.');
            });
            
            // 'frame' 이벤트: 서버로부터 비디오 프레임 데이터를 받았을 때
            socket.on('frame', (data) => {
                const img = new Image();
                // 이미지가 로드되면 캔버스에 그립니다.
                img.onload = () => {
                    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
                };
                // 받은 base64 데이터를 이미지 소스로 설정합니다.
                img.src = 'data:image/jpeg;base64,' + data.data;
            });
            
            // 'disconnect' 이벤트: 서버와의 연결이 끊겼을 때
            socket.on('disconnect', () => {
                console.log('서버와의 연결이 끊겼습니다.');
            });

            // 'connect_error' 이벤트: 연결 중 오류가 발생했을 때
            socket.on('connect_error', (error) => {
                console.error('연결 오류:', error);
            });
        }
        
        // 페이지 로드 시 바로 연결을 시작합니다.
        connect();
        
        // 페이지를 닫거나 새로고침할 때 소켓 연결을 정리합니다.
        window.addEventListener('beforeunload', () => {
            if (socket) {
                socket.disconnect();
            }
        });
    </script>
</body>
</html>
  `);
});

// 서버 시작
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Socket.IO Streaming Server running on port ${PORT}`);
  console.log(`💊 Health check: http://localhost:${PORT}/health`);
  console.log(`📺 Waiting for client connections...`);
});

// 종료 시 정리
process.on('SIGINT', () => {
  console.log('\nShutting down server...');
  stopWebcamStream();
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});