import React, { createContext, useState, useMemo } from 'react';

// Context에 들어갈 데이터의 타입을 정의합니다.

export interface OnoffContextType {
    hlight: boolean;
    setHlight: React.Dispatch<React.SetStateAction<boolean>>;
    glight: boolean;
    setGlight: React.Dispatch<React.SetStateAction<boolean>>;
    w1: boolean;
    setW1: React.Dispatch<React.SetStateAction<boolean>>;
    w2: boolean;
    setW2: React.Dispatch<React.SetStateAction<boolean>>;
    fan1: boolean;
    setFan1: React.Dispatch<React.SetStateAction<boolean>>;
    fan2: boolean;
    setFan2: React.Dispatch<React.SetStateAction<boolean>>;
    door: boolean;
    setDoor: React.Dispatch<React.SetStateAction<boolean>>;
}

// MyContext를 생성하면서 데이터 타입을 명시하고 초기값을 설정합니다.
export const OnoffContext = createContext<OnoffContextType>({
    hlight: false,
    setHlight: () => {}, 
    glight: false,
    setGlight: () => {}, 
    w1: false,
    setW1: () => {}, 
    w2: false,
    setW2: () => {}, 
    fan1: false,
    setFan1: () => {}, 
    fan2: false,
    setFan2: () => {}, 
    door: false,
    setDoor: () => {}, 
});

const OnoffContextProvider: React.FC<{children: React.ReactNode}> = ({ children }) => {
  const [hlight, setHlight] = useState<boolean>(false);
  const [glight, setGlight] = useState<boolean>(false);
  const [w1, setW1] = useState<boolean>(false);
  const [w2, setW2] = useState<boolean>(false);
  const [fan1, setFan1] = useState<boolean>(false);
  const [fan2, setFan2] = useState<boolean>(false);
  const [door, setDoor] = useState<boolean>(false);

    const value = useMemo(() => ({
        hlight,
        setHlight,
        glight,
        setGlight,
        w1,
        setW1,
        w2,
        setW2,
        fan1,
        setFan1,
        fan2,
        setFan2,
        door,
        setDoor
    }), [hlight, glight, w1, w2, fan1, fan2, door]); 

    return (
        <OnoffContext.Provider value={value}>
            {children}
        </OnoffContext.Provider>
    );
}

export default OnoffContextProvider;
