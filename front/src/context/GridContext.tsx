import React, { createContext, useState, useMemo } from 'react';

// Context에 들어갈 데이터의 타입을 정의합니다.
interface GridCoords {
    nx: number;
    ny: number;
}

export interface GridContextType {
    gridCoords: GridCoords;
    setGridCoords: React.Dispatch<React.SetStateAction<GridCoords>>;
}

// MyContext를 생성하면서 데이터 타입을 명시하고 초기값을 설정합니다.
export const GridContext = createContext<GridContextType>({
    gridCoords: { nx: 61, ny: 127 },
    setGridCoords: () => {}, 
});

const GridContextProvider: React.FC<{children: React.ReactNode}> = ({ children }) => {
  const [gridCoords, setGridCoords] = useState<GridCoords>({ nx: 61, ny: 127 });

  const value = useMemo(() => ({
        gridCoords,
        setGridCoords,
    }), [gridCoords]);

    return (
        <GridContext.Provider value={value}>
            {children}
        </GridContext.Provider>
    );
}

export default GridContextProvider;
