// @ts-nocheck
import React, { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
interface CaptureData {
  message: string;
  filename: string;
  path: string;
  timestamp: number;
  imageData: string;
}

const WebcamStreamClient = () => {
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState('');
  const [capturedImage, setCapturedImage] = useState<CaptureData | null>(null);
  const [showModal, setShowModal] = useState(false);
  
  const canvasRef = useRef(null);
  const socketRef = useRef(null);
  const containerRef = useRef(null);

  const SERVER_URL = 'http://192.168.186.179:4000';

  useEffect(() => {
    connectToServer();

    return () => {
      disconnectFromServer();
    };
  }, []);

  const connectToServer = () => {
    try {
      // Socket.IO 클라이언트 생성
      const socket = io(SERVER_URL, {
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionAttempts: 5
      });

      socketRef.current = socket;

      // 연결 성공
      socket.on('connect', () => {
        console.log('Connected to server:', socket.id);
        setIsConnected(true);
        setError('');
      });

      // 서버 확인 메시지
      socket.on('connected', (data) => {
        console.log('Server confirmed:', data);
      });

      // 프레임 수신
      socket.on('frame', (data) => {  
        // 캔버스에 프레임 렌더링
        const canvas = canvasRef.current;
        if (canvas) {
          const ctx = canvas.getContext('2d');
          const img = new Image();
          
          img.onload = () => {
            ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
          };
          
          img.onerror = () => {
            console.error('Failed to load frame');
          };
          
          img.src = `data:image/jpeg;base64,${data.data}`;
        }
      });
      // 캡쳐 성공 이벤트
      socket.on('captureSuccess', (data: CaptureData) => {
        console.log('📸 Captured:', data.filename);
        setCapturedImage(data);
        setShowModal(true);
      });

      // 캡쳐 실패 이벤트
      socket.on('captureError', (data) => {
        console.error('❌ Capture failed:', data);
        alert(`캡쳐 실패: ${data.message}`);
      });
      // 연결 해제
      socket.on('disconnect', () => {
        console.log('Disconnected from server');
        setIsConnected(false);
      });

      // 연결 오류
      socket.on('connect_error', (err) => {
        console.error('Connection error:', err.message);
        setError('서버에 연결할 수 없습니다');
        setIsConnected(false);
      });

      // 일반 오류
      socket.on('error', (err) => {
        console.error('Socket error:', err);
        setError('소켓 오류가 발생했습니다');
      });

    } catch (err) {
      console.error('Failed to create socket:', err);
      setError('소켓 생성 실패');
    }
  };

  const disconnectFromServer = () => {
    if (socketRef.current) {
      socketRef.current.disconnect();
      socketRef.current = null;
    }
  };

  const handleReconnect = () => {
    disconnectFromServer();
    setTimeout(() => {
      connectToServer();
    }, 500);
  };
    // 캡쳐 핸들러
  const handleCapture = () => {
    if (!socketRef.current || !isConnected) {
      alert('스트림에 연결되지 않았습니다.');
      return;
    }

    socketRef.current.emit('captureFrame', {
      filename: `capture_${Date.now()}.jpg`,
    });
  };
  // 모달 닫기
  const closeModal = () => {
    setShowModal(false);
  };

  // 이미지 다운로드
  const downloadImage = () => {
    if (!capturedImage) return;

    const link = document.createElement('a');
    link.href = capturedImage.imageData;
    link.download = capturedImage.filename;
    link.click();
  };

  return (
  <div ref={containerRef}>
    <canvas ref={canvasRef} width="640" height="480"/><div>
      <button onClick={handleReconnect} disabled={isConnected}>
        🔄 재연결
      </button>
      <button onClick={handleCapture} disabled={!isConnected}>
        📸 캡쳐</button>
    </div>
    {showModal && capturedImage && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.8)',
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            zIndex: 1000,
          }}
          onClick={closeModal}
        >
          <div
            style={{
              backgroundColor: 'white',
              borderRadius: '12px',
              padding: '20px',
              maxWidth: '90%',
              maxHeight: '90%',
              overflow: 'auto',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ marginBottom: '15px', textAlign: 'right' }}>
              <button
                onClick={closeModal}
                style={{
                  padding: '8px 16px',
                  fontSize: '14px',
                  backgroundColor: '#f44336',
                  color: 'white',
                  border: 'none',
                  borderRadius: '5px',
                  cursor: 'pointer',
                  marginRight: '10px',
                }}
              >
                ✕ 닫기
              </button>
              <button
                onClick={downloadImage}
                style={{
                  padding: '8px 16px',
                  fontSize: '14px',
                  backgroundColor: '#4CAF50',
                  color: 'white',
                  border: 'none',
                  borderRadius: '5px',
                  cursor: 'pointer',
                }}
              >
                💾 다운로드
              </button>
            </div>

            <div style={{ textAlign: 'center' }}>
              <img src={capturedImage.imageData}/>
            </div>
          </div>
        </div>
      )}
  </div>
  
  );
};

export default WebcamStreamClient;