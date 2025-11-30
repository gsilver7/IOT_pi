import React from "react";
import { useNavigate } from "react-router-dom";
import { logout } from "./Logout"; // 아까 만든 logout.ts 파일 경로로 맞춰주세요!

interface LogoutButtonProps {
  className?: string; // 외부에서 스타일을 추가할 수 있게 뚫어둠
}

export const LogoutButton: React.FC<LogoutButtonProps> = ({ className }) => {
  const navigate = useNavigate();

  const handlePress = () => {
    // 확인 창을 띄우고 싶다면 여기서 window.confirm 사용
    if (window.confirm("정말 로그아웃 하시겠습니까?")) {
      logout(navigate);
    }
  };

  return (
    <button
      onClick={handlePress}
      className={className} // 외부에서 넘겨준 클래스 적용 (Tailwind 등)
      style={defaultStyle} // 기본 스타일 (필요 없으면 삭제)
    >
      로그아웃
    </button>
  );
};

// (선택사항) 기본 CSS 스타일
const defaultStyle: React.CSSProperties = {
  backgroundColor: "#ff4d4f", // 빨간색
  color: "white",
  border: "none",
  padding: "8px 16px",
  borderRadius: "4px",
  cursor: "pointer",
  fontWeight: "bold",
};
