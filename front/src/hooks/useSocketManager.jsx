import useSocket from './useSocket'; // 1. 재사용할 useSocket 훅을 import

const useSocketManager = (baseURL) => {
  // 2. useSocket 훅을 재사용하여 chatSocket 생성
  const chatSocket = useSocket(`${baseURL}/chat`);
  
  // 3. useSocket 훅을 재사용하여 webrtcSocket 생성
  const webrtcSocket = useSocket(`${baseURL}/webrtc`);

  // 4. 두 소켓을 객체로 묶어 반환
  return { chatSocket, webrtcSocket };
};

export default useSocketManager;