import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import GridContextProvider from "./context/GridContext";
import OnoffContextProvider from "./context/OnoffContextProvider.tsx";
import Register from "./pages/Register.tsx";
import Login from "./pages/Login.tsx";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
// Context를 사용하기 위해 RootComponent를 생성합니다.
import Info from "./pages/Info.tsx";
import Visitor from "./pages/Visitor.tsx";
import Door from "./pages/Door.tsx";
import Control from "./pages/Control.tsx";
import MainLayout from "./MainLayout.tsx";
import { useState } from "react";
import { Global } from "@emotion/react";
import globalStyles from "./styles/globalStyles";
import Home from "./pages/Home.tsx";
import Mode from "./pages/Mode.tsx";
import { Socketmain } from "./Sockermain.tsx";
import Refresh from "./components/Refresh.tsx";
import { GlobalStateProvider } from "./context/GlobalStateContext.tsx";

const PrivateRoute = ({ children }: { children: React.ReactNode }) => {
  const token = localStorage.getItem("token");
  return token ? children : <Navigate to="/login" replace />;
};

export const RootComponent = () => {
  const [toggle, setToggle] = useState<boolean>(false);
  const [homemode, setHomemode] = useState<string>("홈");
  // 1. useState를 사용하여 gridCoords 상태를 관리합니다.

  return (
    <BrowserRouter>
      <Refresh />
      <GlobalStateProvider>
      <GridContextProvider>
        <OnoffContextProvider>
          <Socketmain />
          <Global styles={globalStyles} />
          <></>
          <Routes>
            <Route path="/register" element={<Register />} />
            <Route path="/login" element={<Login />} />
            <Route
              element={
                <PrivateRoute>
                  <MainLayout
                    toggle={toggle}
                    setToggle={setToggle}
                    homemode={homemode}
                    setHomemode={setHomemode}
                  />
                </PrivateRoute>
              }
            >
              {/* 자식 Route들: MainLayout의 <Outlet /> 자리에 들어갑니다.
                 path="/"는 index로 표시해도 됩니다.
              */}

              <Route path="/" element={<Home />} />
              <Route path="/mode" element={<Mode />} />
              <Route path="/info" element={<Info />} />
              <Route path="/sensor" element={<App />} />
              <Route path="/visitor" element={<Visitor />} />
              <Route path="/door" element={<Door />} />
              <Route path="/control" element={<Control />} />
            </Route>
          </Routes>
        </OnoffContextProvider>
      </GridContextProvider>
    </GlobalStateProvider>
    </BrowserRouter>
  );
};

// <RootComponent>를 렌더링합니다.
createRoot(document.getElementById("root")!).render(<RootComponent />);
