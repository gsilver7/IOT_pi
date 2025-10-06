import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import GridContextProvider from './context/GridContext';
import OnoffContextProvider from './context/OnoffContext';

// Context를 사용하기 위해 RootComponent를 생성합니다.
const RootComponent = () => {
    // 1. useState를 사용하여 gridCoords 상태를 관리합니다.
    


    return (
        <GridContextProvider>
            <OnoffContextProvider>
                <App />
            </OnoffContextProvider>
        </GridContextProvider>
    );
};

// <RootComponent>를 렌더링합니다.
createRoot(document.getElementById('root')!).render(<RootComponent />);

