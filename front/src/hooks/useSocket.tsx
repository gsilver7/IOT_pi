// useSocket.tsx 파일
import { useEffect, useState } from 'react';
import { io, Socket } from 'socket.io-client';

const useSocket = (url: string) => {
  // ✅ Socket 타입에 DefaultEventsMap이 기본으로 포함되므로 별도로 명시하지 않아도 됩니다.
  const [socket, setSocket] = useState<Socket | null>(null);

  useEffect(() => {
    const newSocket: Socket = io(url, {
    transports: ['websocket', 'polling'],
    timeout: 10000,
    autoConnect: true,
    forceNew: false,
    });
    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, [url]);

  return socket;
};

export default useSocket;