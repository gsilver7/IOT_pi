// server.js - MJPEG 스트리밍 서버 (권장)
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const ffmpeg = require('fluent-ffmpeg');

const app = express();
app.use(cors());
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

const PORT = 4000;

// 정적 파일 제공
app.use(express.static('public'));

// MJPEG 스트림 엔드포인트
app.get('/stream', (req, res) => {
  console.log('Client connected to MJPEG stream');
  
  res.writeHead(200, {
    'Content-Type': 'multipart/x-mixed-replace; boundary=--myboundary',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*'
  });

  const command = ffmpeg('/dev/video0')
    .inputOptions(['-re', '-f', 'v4l2'])
    .size('640x480')
    .fps(15)  // 프레임률 제한으로 부하 줄이기
    .videoCodec('mjpeg')
    .outputOptions([
      '-f', 'mjpeg',
      '-q:v', '3',  // 품질 설정 (1=최고, 5=보통)
      '-huffman', 'optimal'
    ]);

  command
    .on('start', (cmdline) => {
      console.log('FFmpeg started:', cmdline);
    })
    .on('error', (err) => {
      console.error('FFmpeg error:', err.message);
      res.end();
    })
    .on('end', () => {
      console.log('FFmpeg stream ended');
      res.end();
    });

  const stream = command.pipe();
  let frameCount = 0;

  stream.on('data', (chunk) => {
    frameCount++;
    if (frameCount % 100 === 0) {
      console.log(`Streamed ${frameCount} frames`);
    }
    
    try {
      res.write('--myboundary\r\n');
      res.write('Content-Type: image/jpeg\r\n');
      res.write(`Content-Length: ${chunk.length}\r\n\r\n`);
      res.write(chunk);
      res.write('\r\n');
    } catch (writeError) {
      console.error('Write error:', writeError.message);
      command.kill('SIGKILL');
      res.end();
    }
  });

  stream.on('error', (err) => {
    console.error('Stream error:', err.message);
    res.end();
  });

  req.on('close', () => {
    console.log('Client disconnected from MJPEG stream');
    command.kill('SIGKILL');
  });

  req.on('error', (err) => {
    console.error('Request error:', err.message);
    command.kill('SIGKILL');
  });
});

// 테스트용 HTML 페이지
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>USB Camera Stream Test</title>
        <style>
            body { 
                margin: 0; 
                padding: 20px; 
                font-family: Arial, sans-serif;
                background: #f0f0f0;
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            img { 
                max-width: 100%; 
                height: auto; 
                border: 2px solid #333;
                border-radius: 8px;
                background: #000;
            }
            .status {
                display: flex;
                align-items: center;
                gap: 10px;
                margin-bottom: 15px;
            }
            .indicator {
                width: 12px;
                height: 12px;
                border-radius: 50%;
                background: #4CAF50;
                animation: pulse 2s infinite;
            }
            @keyframes pulse {
                0% { opacity: 1; }
                50% { opacity: 0.5; }
                100% { opacity: 1; }
            }
            button {
                padding: 8px 16px;
                background: #2196F3;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                margin-left: 10px;
            }
            button:hover {
                background: #1976D2;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎥 USB 웹캠 라이브 스트림</h1>
            <div class="status">
                <div class="indicator"></div>
                <span>스트리밍 중</span>
                <button onclick="location.reload()">새로고침</button>
            </div>
            <img src="/stream" alt="Live Stream" id="streamImg" />
            <div style="margin-top: 15px; font-size: 14px; color: #666;">
                <p><strong>스트림 URL:</strong> <code>http://localhost:${PORT}/stream</code></p>
                <p><strong>해상도:</strong> 640x480 @ 15fps</p>
                <p><strong>포맷:</strong> MJPEG over HTTP</p>
            </div>
        </div>
        
        <script>
            const img = document.getElementById('streamImg');
            const indicator = document.querySelector('.indicator');
            
            img.onload = () => {
                indicator.style.background = '#4CAF50';
                console.log('Stream loaded successfully');
            };
            
            img.onerror = () => {
                indicator.style.background = '#F44336';
                console.error('Stream load failed');
                setTimeout(() => {
                    img.src = '/stream?t=' + Date.now();
                }, 5000);
            };
        </script>
    </body>
    </html>
  `);
});

// WebSocket 연결 (선택사항 - 상태 모니터링용)
io.on('connection', (socket) => {
  console.log(`WebSocket client connected: ${socket.id}`);
  
  socket.emit('server_status', {
    status: 'ready',
    streamUrl: '/stream',
    timestamp: Date.now()
  });
  
  socket.on('disconnect', () => {
    console.log(`WebSocket client disconnected: ${socket.id}`);
  });
});

// 헬스체크 엔드포인트
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: Date.now(),
    streams: {
      mjpeg: '/stream'
    }
  });
});

server.listen(PORT, () => {
  console.log(`🚀 MJPEG Streaming Server running on port ${PORT}`);
  console.log(`📺 Stream URL: http://localhost:${PORT}/stream`);
  console.log(`🌐 Test page: http://localhost:${PORT}/`);
  console.log(`💊 Health check: http://localhost:${PORT}/health`);
});