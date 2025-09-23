import { useEffect, useRef } from 'react';

import useSocket from './hooks/useSocket';
import { socketState, messageState } from './atoms';

const SocketManager = ({ url, sendMessage }) => {
  const socket = useSocket(url);
  const setSocket = useSetRecoilState(socketState);
  const setMessages = useSetRecoilState(messageState);
  const prevSendMessageRef = useRef(null); // 이전 sendMessage 값 저장

  useEffect(() => {
    if (socket) {
      setSocket(socket); // Recoil에 소켓 저장

      // 메시지 수신 이벤트 등록
      socket.on('message', (data) => {
        setMessages((prevMessages) => [...prevMessages, data]);
      });

      socket.on('disconnect', () => {
        console.log('Socket disconnected');
      });
    }

    return () => {
      if (socket) {
        socket.off('message');
        socket.off('disconnect');
      }
    };
  }, [socket, setSocket, setMessages]);

  useEffect(() => {
    // sendMessage가 바뀌었을 때만 emit 하도록 (중복 전송 방지)
    if (socket && sendMessage && prevSendMessageRef.current !== sendMessage) {
      socket.emit('message', sendMessage);
      prevSendMessageRef.current = sendMessage;
    }
  }, [sendMessage, socket]);

  return null; // UI 없음
};

export default SocketManager;
