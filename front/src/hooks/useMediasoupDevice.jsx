  import { useEffect, useState } from 'react';
  import * as mediasoupClient from 'mediasoup-client';

  export const useMediasoupDevice = (socket) => {
    const [device, setDevice] = useState(null);

    useEffect(() => {
      if (!socket) return;
      
      // 1. 서버로부터 router의 정보를 받으면 device를 생성하는 핸들러
      const handleRouterCapabilities = async (routerRtpCapabilities) => {
        // 서버에서 에러 객체를 반환할 경우 처리
        if (routerRtpCapabilities.error) {
          console.error('Router Capabilities 수신 에러:', routerRtpCapabilities.error);
          return;
        }
        
        try {
          const newDevice = new mediasoupClient.Device();
          // newDevice.load()를 위해 서버 응답 사용
          await newDevice.load({ routerRtpCapabilities });
          setDevice(newDevice);
          console.log('Mediasoup Device 로드 완료');
        } catch (error) {
          console.error('Device 로드 실패:', error);
        }
      };

      // 2. 서버의 응답 리스너 설정
      socket.on('getRouterRtpCapabilities', handleRouterCapabilities);

      // 3. 서버에 요청 보내기 (추가된 핵심 로직)
      console.log('>>> 서버에 getRouterRtpCapabilities 요청 전송');
      // 서버의 이벤트 핸들러와 정확히 일치해야 합니다.
      socket.emit('getRouterRtpCapabilities', (response) => {
          // 응답을 콜백으로 받으면, handleRouterCapabilities가 아닌 이 곳에서 처리하거나
          // 서버가 응답을 'routerRtpCapabilities' 이벤트로 보내도록 해야 합니다.
          // NestJS의 @SubscribeMessage은 return 값을 응답으로 보내므로, 콜백으로 처리합니다.
          handleRouterCapabilities(response);
      });
      
      return () => {
        socket.off('getRouterRtpCapabilities', handleRouterCapabilities);
      };
    }, [socket]);

    return device;
  };
