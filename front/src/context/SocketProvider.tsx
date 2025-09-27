import React, { createContext } from 'react';
import useSocketManager from '../hooks/useSocketManager'; // 1. 방금 만든 훅을 import

// 2. Context 객체 생성
const SocketContext = createContext(null);

const BASE_URL = 'http://192.168.137.154:4000/'; // 서버 주소

// 3. Provider 컴포넌트 정의
export const SocketProvider = ({ children }) => {
  // 4. useSocketManager 훅을 여기서 단 한번만 호출
  const sockets = useSocketManager(BASE_URL);

  return (
    // 5. 훅이 반환한 sockets 객체를 value로 하위 컴포넌트에 제공
    <SocketContext.Provider value={sockets}>
      {children}
    </SocketContext.Provider>
  );
};
