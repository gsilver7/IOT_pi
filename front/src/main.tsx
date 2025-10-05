import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import React, { createContext, useState, useMemo } from 'react';

// Context에 들어갈 데이터의 타입을 정의합니다.
interface GridCoords {
    nx: number;
    ny: number;
}

export interface MyContextType {
    gridCoords: GridCoords;
    setGridCoords: React.Dispatch<React.SetStateAction<GridCoords>>;
}

// MyContext를 생성하면서 데이터 타입을 명시하고 초기값을 설정합니다.
const MyContext = createContext<MyContextType>({
    gridCoords: { nx: 61, ny: 127 },
    // 초기화 함수는 의미 있는 값을 가질 수 없으므로 빈 함수로 설정합니다.
    setGridCoords: () => {}, 
});

// Context를 사용하기 위해 RootComponent를 생성합니다.
const RootComponent = () => {
    // 1. useState를 사용하여 gridCoords 상태를 관리합니다.
    const [gridCoords, setGridCoords] = useState<GridCoords>({ nx: 61, ny: 127 });

    // 2. Context에 제공할 value 객체를 useMemo로 메모이제이션하여 불필요한 리렌더링을 방지합니다.
    const value = useMemo(() => ({
        gridCoords,
        setGridCoords,
    }), [gridCoords]); // gridCoords 값이 변경될 때만 value 객체를 새로 만듭니다.

    // 3. <MyContext.Provider>를 사용하여 App 컴포넌트를 감싸고 value를 전달합니다.
    return (
        <MyContext.Provider value={value}>
            <App />
        </MyContext.Provider>
    );
};

// <RootComponent>를 렌더링합니다.
createRoot(document.getElementById('root')!).render(<RootComponent />);

export default MyContext;