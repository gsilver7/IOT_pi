import axios from "axios";
import type { NavigateFunction } from "react-router-dom"; // 1. 타입 import

// navigate 매개변수에 타입 지정
export const logout = async (navigate: NavigateFunction) => {
  try {
    const token = localStorage.getItem("token");

    if (token) {
      await axios.post(
        "http://kmj.shscript.com/api/auth/logout",
        {},
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );
      console.log("서버 로그아웃 요청 성공");
    }
  } catch (error) {
    // 2. error를 Error 타입으로 단언(Type Assertion)
    // 또는 (error as any).message 로 해도 됨
    const err = error as Error;
    console.warn("서버 로그아웃 실패 (무시하고 진행):", err.message);
  } finally {
    localStorage.removeItem("token");
    localStorage.removeItem("refreshToken");
    localStorage.removeItem("userId");

    alert("로그아웃 되었습니다.");

    if (navigate) {
      navigate("/login");
    }
  }
};
