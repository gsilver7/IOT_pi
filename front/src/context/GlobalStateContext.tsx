// GlobalStateContext.tsx
import React, { createContext, useContext, useState, useEffect, useRef,useCallback } from 'react';
import { OnoffContext } from "./OnoffContext";



interface GlobalStateContextType {
  modetype: string;
  triggerStateB: (matched:boolean) => void;
  setModetype: React.Dispatch<React.SetStateAction<string>>;
}

const GlobalStateContext = createContext<GlobalStateContextType | undefined>(undefined);

export const GlobalStateProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { light } = useContext(OnoffContext);
  const [modetype, setModetype] = useState<string>("sudong");
  const timerRef = useRef<number | null>(null);
  const modetypeRef = useRef(modetype); // 👈 최신 modetype을 추적
  const lightRef = useRef(light); // 👈 최신 modetype을 추적

  useEffect(() => {
    modetypeRef.current = modetype;
  }, [modetype]);

  useEffect(() => {
    lightRef.current = light;
  }, [light]);

  const triggerStateB = useCallback((matched:boolean) => {
    
    if (modetypeRef.current== 'sudong'){
      console.log("수동에서는 변경불가!");
      return;
    }

    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }


    if (matched == false){
      console.log("외출");
      setModetype('out');
      return;
    }
    const lightValue = parseInt(lightRef.current); // parseInt 사용
    console.log(lightValue);
    if (lightValue<500){
      console.log("주무셈");
      setModetype('zzz');
      return;
    }

    console.log("아침입니다!");
    console.log('🔄 상태를 in으로 변경');
    setModetype('in');
    
    // 기존 타이머 클리어
    
    
    // 1분 후 자동으로 A로 복귀
    timerRef.current = window.setTimeout(() => {
      console.log('⏰ 1분 경과 - 상태를 out로 복귀');
      setModetype('out');
      timerRef.current = null; // 타이머 완료 후 정리
    }, 60000); // 60초
  },[]);

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