import React from 'react';

const SimpleStreamTest: React.FC = () => {
  return (
    <div style={{ 
      padding: '20px', 
      textAlign: 'center',
      fontFamily: 'Arial, sans-serif'
    }}>
      <h1>USB 웹캠 스트림 테스트</h1>
      
      <div style={{ 
        marginBottom: '20px',
        padding: '15px',
        backgroundColor: '#f0f8ff',
        borderRadius: '8px',
        border: '1px solid #cce7ff'
      }}>
        <p>서버가 <code>http://localhost:4000</code>에서 실행 중이어야 합니다.</p>
        <p>웹캠이 <code>/dev/video0</code>에 연결되어 있어야 합니다.</p>
      </div>

      <div style={{ 
        maxWidth: '640px', 
        margin: '0 auto',
        border: '2px solid #333',
        borderRadius: '8px',
        overflow: 'hidden',
        backgroundColor: '#000'
      }}>
        <img 
          src="http://localhost:4000/stream" 
          alt="웹캠 스트림"
          style={{ 
            width: '100%', 
            height: 'auto',
            display: 'block'
          }}
          onLoad={() => console.log('스트림 로드됨')}
          onError={(e) => {
            console.error('스트림 로드 실패');
            // 5초 후 재시도
            setTimeout(() => {
              (e.target as HTMLImageElement).src = 
                `http://localhost:4000/stream?t=${Date.now()}`;
            }, 5000);
          }}
        />
      </div>

      <div style={{ marginTop: '20px', fontSize: '14px', color: '#666' }}>
        <p>스트림이 보이지 않으면 페이지를 새로고침해보세요.</p>
        <p>또는 직접 <a href="http://localhost:4000/" target="_blank" rel="noopener noreferrer">서버 테스트 페이지</a>를 확인하세요.</p>
      </div>
    </div>
  );
};

export default SimpleStreamTest;