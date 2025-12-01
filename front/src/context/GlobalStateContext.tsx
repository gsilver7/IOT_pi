// GlobalStateContext.tsx
import React, { createContext, useContext, useState, useEffect, useRef } from 'react';


interface GlobalStateContextType {
  modetype: string;
  triggerStateB: () => void;
  setModetype: React.Dispatch<React.SetStateAction<string>>;
}

const GlobalStateContext = createContext<GlobalStateContextType | undefined>(undefined);

export const GlobalStateProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [modetype, setModetype] = useState<string>("sudong");
  const timerRef = useRef<number | null>(null);


  const triggerStateB = () => {
    console.log('🔄 상태를 in으로 변경');
    setModetype('in');
    
    // 기존 타이머 클리어
    if (timerRef.current) {
      clearTimeout(timerRef.current);
    }
    
    // 1분 후 자동으로 A로 복귀
    timerRef.current = window.setTimeout(() => {
      console.log('⏰ 1분 경과 - 상태를 out로 복귀');
      setModetype('out');
    }, 60000); // 60초
  };

  // 컴포넌트 언마운트 시 타이머 정리
  useEffect(() => {
    return () => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
      }
    };
  }, []);

  return (
    <GlobalStateContext.Provider value={{ modetype, setModetype, triggerStateB }}>
      {children}
    </GlobalStateContext.Provider>
  );
};

export const useGlobalState = () => {
  const context = useContext(GlobalStateContext);
  if (!context) {
    throw new Error('useGlobalState must be used within GlobalStateProvider');
  }
  return context;
};