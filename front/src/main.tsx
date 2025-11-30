import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import GridContextProvider from "./context/GridContext";
import OnoffContextProvider from "./context/OnoffContextProvider.tsx";
import Register from "./pages/Register.tsx";
import Login from "./pages/Login.tsx";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
// Context를 사용하기 위해 RootComponent를 생성합니다.

const PrivateRoute = ({ children }: { children: React.ReactNode }) => {
  const token = localStorage.getItem("token");
  return token ? children : <Navigate to="/login" replace />;
};

export const RootComponent = () => {
  // 1. useState를 사용하여 gridCoords 상태를 관리합니다.

  return (
    <BrowserRouter>
      <GridContextProvider>
        <OnoffContextProvider>
          <Routes>
            <Route path="/register" element={<Register />} />
            <Route path="/login" element={<Login />} />

            <Route
              path="/"
              element={
                <PrivateRoute>
                  <App />
                </PrivateRoute>
              }
            />
          </Routes>
        </OnoffContextProvider>
      </GridContextProvider>
    </BrowserRouter>
  );
};

// <RootComponent>를 렌더링합니다.
createRoot(document.getElementById("root")!).render(<RootComponent />);
