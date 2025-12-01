// @ts-nocheck
import React, { useState, useEffect, useRef } from 'react';
import styled from '@emotion/styled';
import { io } from 'socket.io-client';

interface CaptureData {
  message: string;
  filename: string;
  path: string;
  timestamp: number;
  imageData: string;
}

// ─── [스타일 정의 시작] ───

// 1. 전체 레이아웃 컨테이너 (중앙 정렬)
const Container = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  width: 100%;
  padding: 20px 0;
`;

// 2. 화면 비디오를 감싸는 틀 (반응형 핵심)
const VideoWrapper = styled.div`
  /* PC 화면 기본 너비: 50% */
  width: 50%;
  
  background-color: #000; /* 영상 로딩 전 검은 배경 */
  border-radius: 12px;    /* 둥근 모서리 */
  overflow: hidden;       /* 둥근 모서리 적용을 위해 넘치는 부분 숨김 */
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2); /* 그림자 효과 */

  /* 태블릿/노트북 (1200px 이하): 70%로 확대 */
  @media (max-width: 1200px) {
    width: 70%;
  }

  /* 모바일 (768px 이하): 95%로 확대 (거의 꽉 차게) */
  @media (max-width: 768px) {
    width: 95%;
  }

  /* 내부 캔버스 스타일 강제 적용 */
  canvas {
    width: 100% !important;  /* 부모(Wrapper) 너비에 맞춤 */
    height: auto !important; /* 비율 유지하며 높이 자동 조절 */
    display: block;          /* 하단 여백 제거 */
  }
`;

// 3. 버튼 그룹 스타일
const ButtonGroup = styled.div`
  margin-top: 20px;
  display: flex;
  gap: 15px;
`;

// ─── [스타일 정의 끝] ───

const WebcamStreamClient = () => {
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState('');
  const [capturedImage, setCapturedImage] = useState<CaptureData | null>(null);
  const [showModal, setShowModal] = useState(false);
  
  const canvasRef = useRef(null);
  const socketRef = useRef(null);
  const containerRef = useRef(null);

  const SERVER_URL = 'https://kmj.shscript.com';

  useEffect(() => {
    connectToServer();

    return () => {
      disconnectFromServer();
    };
  }, []);

  const compareFace = async () => {
    if (!capturedImage) return;

    try {
      const response = await fetch('https://kmj.shscript.com/api/face/compare', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          imageData: capturedImage.imageData
        })
      });

      const result = await response.json();
      
      if (response.ok) {
        alert('얼굴이 성공적으로 등록되었습니다!');
      } else {
        alert(`등록 실패: ${result.message}`);
      }
    } catch (error) {
      console.error('얼굴 등록 에러:', error);
      alert('얼굴 등록 중 오류가 발생했습니다.');
    }
  };

  const registerFace = async () => {
    if (!capturedImage) return;

    try {
      const response = await fetch('https://kmj.shscript.com/api/face/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          imageData: capturedImage.imageData
        })
      });

      const result = await response.json();
      
      if (response.ok) {
        alert('얼굴이 성공적으로 등록되었습니다!');
        closeModal();
      } else {
        alert(`등록 실패: ${result.message}`);
      }
    } catch (error) {
      console.error('얼굴 등록 에러:', error);
      alert('얼굴 등록 중 오류가 발생했습니다.');
    }
  };

  const connectToServer = () => {
    try {
      const socket = io(SERVER_URL, {
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionAttempts: 5
      });

      socketRef.current = socket;

      socket.on('connect', () => {
        console.log('Connected to server:', socket.id);
        setIsConnected(true);
        setError('');
      });

      socket.on('connected', (data) => {
        console.log('Server confirmed:', data);
      });

      socket.on('frame', (data) => {
        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');

        const img = new Image();
        
        img.onload = () => {
          ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        };

        img.onerror = (error) => {
          console.error('이미지 로드 실패:', error);
        };

        img.src = `data:image/jpeg;base64,${data.data}`;
      });

      socket.on('captureSuccess', (data: CaptureData) => {
        console.log('📸 Captured:', data.filename);
        setCapturedImage(data);
        setShowModal(true);
      });

      socket.on('captureError', (data) => {
        console.error('❌ Capture failed:', data);
        alert(`캡쳐 실패: ${data.message}`);
      });

      socket.on('disconnect', () => {
        console.log('Disconnected from server');
        setIsConnected(false);
      });

      socket.on('connect_error', (err) => {
        console.error('Connection error:', err.message);
        setError('서버에 연결할 수 없습니다');
        setIsConnected(false);
      });

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

  const handleCapture = () => {
    if (!socketRef.current || !isConnected) {
      alert('스트림에 연결되지 않았습니다.');
      return;
    }

    socketRef.current.emit('captureFrame', {
      filename: `capture_${Date.now()}.jpg`,
    });
  };

  const closeModal = () => {
    setShowModal(false);
  };

  const downloadImage = () => {
    if (!capturedImage) return;

    const link = document.createElement('a');
    link.href = capturedImage.imageData;
    link.download = capturedImage.filename;
    link.click();
  };

  return (
    <Container ref={containerRef}>
      {/* VideoWrapper가 화면 크기에 따라 50% -> 70% -> 95%로 변합니다.
         내부 canvas는 width: 100%로 설정되어 Wrapper 크기에 맞춰 늘어납니다.
      */}
      <VideoWrapper>
        <canvas ref={canvasRef} width="640" height="480"/>
      </VideoWrapper>

      <ButtonGroup>
        <button onClick={handleReconnect} disabled={isConnected}>
          🔄 재연결
        </button>
        <button onClick={handleCapture} disabled={!isConnected}>
          📸 캡쳐
        </button>
      </ButtonGroup>

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
              width: '90%',
              maxHeight: '90%',
              maxWidth: '600px', // 모달 최대 너비 제한 추가
              display: 'flex',
              flexDirection: 'column'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ marginBottom: '15px', display: 'flex', flexWrap: 'wrap', gap: '8px', justifyContent: 'flex-end' }}>
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
                }}
              >
                ✕ 닫기
              </button>
              <button
                onClick={registerFace}
                style={{
                  padding: '8px 16px',
                  fontSize: '14px',
                  backgroundColor: '#2196F3',
                  color: 'white',
                  border: 'none',
                  borderRadius: '5px',
                  cursor: 'pointer',
                }}
              >
                👤 얼굴 등록
              </button>
              <button
                onClick={compareFace}
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
                💾 얼굴 비교
              </button>
              <button
                onClick={downloadImage}
                style={{
                  padding: '8px 16px',
                  fontSize: '14px',
                  backgroundColor: '#607D8B',
                  color: 'white',
                  border: 'none',
                  borderRadius: '5px',
                  cursor: 'pointer',
                }}
              >
                📥 다운로드
              </button>
            </div>

            <div style={{ textAlign: 'center', overflow: 'hidden' }}>
              <img 
                src={capturedImage.imageData} 
                style={{ maxWidth: '100%', height: 'auto', borderRadius: '8px' }} 
              />
            </div>
          </div>
        </div>
      )}
    </Container>
  );
};

export default WebcamStreamClient;