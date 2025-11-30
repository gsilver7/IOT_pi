import { useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";

const Refresh = () => {
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    // 1. 브라우저의 네비게이션 타입 확인
    const navigationEntries = performance.getEntriesByType("navigation");
    
    // 2. 타입이 'reload' (새로고침) 인지 확인
    if (navigationEntries.length > 0) {
      const navTiming = navigationEntries[0] as PerformanceNavigationTiming;
      
      if (navTiming.type === 'reload') {
        console.log("🔄 새로고침 감지됨 -> 홈으로 이동");
        
        // 현재 경로가 '/'가 아닐 때만 이동 (무한 루프 방지)
        if (location.pathname !== "/") {
          navigate("/", { replace: true }); // replace: true는 뒤로가기 방지
        }
      }
    }
  }, []); // 빈 배열: 컴포넌트 마운트 시 딱 1번만 실행

  return null; // 화면엔 아무것도 안 그림
};

export default Refresh;