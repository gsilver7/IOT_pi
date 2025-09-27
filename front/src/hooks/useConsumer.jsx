import { useEffect, useRef, useCallback } from 'react';

export const useConsumer = ({ socket, device }) => {
  const videoRef = useRef(null);
  const transportRef = useRef(null);
  const consumerRef = useRef(null);
  
  const payload = {
    forceTcp: false,
    producing: false,
    consuming: true,
  };

  useEffect(() => {
    if (!socket || !device) return;

const handleTransportCreated = async (params) => {
  try {
    console.log('📦 Transport 파라미터:', params);
    
    const newTransport = device.createRecvTransport(params);
    console.log('✅ Consumer Transport 생성:', newTransport.id);
    transportRef.current = newTransport;

    // 🔍 모든 Transport 이벤트 모니터링
    newTransport.on('connect', ({ dtlsParameters }, callback, errback) => {
      console.log('🔗 [CONNECT 이벤트] DTLS 연결 시도...');
      
      socket.emit('connectWebRtcTransport', 
        { transportId: newTransport.id, dtlsParameters },
        (response) => {
          console.log('🔗 [CONNECT 응답]', response);
          if (response.error) {
            console.error('❌ Transport 연결 실패:', response.error);
            errback(new Error(response.error));
          } else {
            console.log('✅ Transport 연결 성공');
            callback();
          }
        }
      );
    });

    // 🔍 모든 상태 변화 로깅
    newTransport.on('connectionstatechange', (state) => {
      console.log('🔄 [CONNECTION STATE]', state);
      if (state === 'connected') {
        requestConsumer(newTransport);
      } else if (state === 'failed') {
        console.error('❌ Transport 연결 실패');
      }
    });

    newTransport.on('iceconnectionstatechange', (state) => {
      console.log('🧊 [ICE STATE]', state);
    });

    newTransport.on('icegatheringstatechange', (state) => {
      console.log('🧊 [ICE GATHERING]', state);
    });

    newTransport.on('dtlsstatechange', (state) => {
      console.log('🔐 [DTLS STATE]', state);
    });

    // 🚀 수동으로 연결 프로세스 시작
    console.log('🚀 수동으로 연결 프로세스 시작...');
    
    // ICE 후보 수집이 완료될 때까지 잠시 대기 후 연결 시도
    setTimeout(async () => {
      console.log('⏰ 타이머 후 Consumer 요청 시도');
      await requestConsumer(newTransport);
    }, 3000);

  } catch (error) {
    console.error('❌ Transport 생성 실패:', error);
  }
};

    // Consumer 생성 요청 함수
    const requestConsumer = async (transport) => {
      try {
        // 백엔드에 Consumer 생성 요청 (올바른 메시지명과 파라미터)
        socket.emit('consume', 
          {
            consumerTransportId: transport.id,  // ✅ 필수 파라미터 추가
            rtpCapabilities: device.rtpCapabilities
          },
          async (response) => {
            if (response.error) {
              console.error('❌ Consumer 생성 실패:', response.error);
              return;
            }

            console.log('✅ Consumer 생성 성공:', response.id);
            
            // Consumer 객체 생성
            const consumer = await transport.consume({
              id: response.id,
              producerId: response.producerId,
              kind: response.kind,
              rtpParameters: response.rtpParameters,
            });

            consumerRef.current = consumer;
            
            // 비디오 트랙을 video 엘리먼트에 연결
            const { track } = consumer;
            if (videoRef.current && track.kind === 'video') {
              const stream = new MediaStream([track]);
              videoRef.current.srcObject = stream;
              console.log('📹 비디오 스트림 연결 완료');
              
            }

            // ✅ Consumer 재개 요청 (중요!)
            socket.emit('resume', {}, (resumeResponse) => {
              if (resumeResponse?.error) {
                console.error('❌ Consumer 재개 실패:', resumeResponse.error);
              } else {
                console.log('▶️ Consumer 재개 성공 - 스트리밍 시작!');
              }
            });
          }
        );
      } catch (error) {
        console.error('❌ Consumer 생성 중 오류:', error);
      }
    };

    // 이벤트 리스너 등록
    socket.on('transportCreated', handleTransportCreated);

    // ✅ 에러 처리 추가
    socket.on('transportFailed', () => {
      console.warn('⚠️ Transport 실패 - 재연결 필요');
      // 재연결 로직 추가 가능
    });

    return () => {
      socket.off('transportCreated', handleTransportCreated);
      socket.off('transportFailed');
      
      // 정리 작업
      if (consumerRef.current) {
        consumerRef.current.close();
      }
      if (transportRef.current) {
        transportRef.current.close();
      }
    };
  }, [socket, device]);

  const startStreaming = useCallback(() => {
    if (!socket) {
      console.error('❌ Socket이 연결되지 않음');
      return;
    }
    
    console.log('🚀 Consumer Transport 생성 요청');
    socket.emit('startTransport', payload, (response) => {
      if (response?.error) {
        console.error('❌ Transport 생성 요청 실패:', response.error);
      } else {
        console.log('✅ Transport 생성 요청 성공');
      }
    });
  }, [socket]);

  // 정리 함수 추가
  const stopStreaming = useCallback(() => {
    if (consumerRef.current) {
      consumerRef.current.close();
      consumerRef.current = null;
    }
    if (transportRef.current) {
      transportRef.current.close();
      transportRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    console.log('🛑 스트리밍 정지');
  }, []);

  return { 
    videoRef, 
    startStreaming, 
    stopStreaming,
    isConnected: !!consumerRef.current 
  };
};