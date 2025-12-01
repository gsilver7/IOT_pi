import { useState, useEffect } from "react";
import axios from "axios";

const BluetoothRegister = () => {
  console.log("렌더됨");

  const [bluetooth, setBluetooth] = useState(""); // 입력된 값
  const [savedBluetooth, setSavedBluetooth] = useState<string | null>(null); // DB에 저장된 값
  const [isEditing, setIsEditing] = useState(false); // 수정 모드 여부
  const [loading, setLoading] = useState(true);

  // 1. 컴포넌트 로딩 시 내 정보(기존 블루투스 값) 가져오기
  useEffect(() => {
    fetchProfile();
  }, []);

  const fetchProfile = async () => {
    try {
      const token = localStorage.getItem("token");
      const response = await axios.get(
        "https://kmj.shscript.com/api/users/profile",
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      const userBluetooth = response.data.bluetooth;
      if (userBluetooth) {
        setSavedBluetooth(userBluetooth);
        setBluetooth(userBluetooth); // 입력창에도 미리 채워줌
        setIsEditing(false); // 값이 있으니까 수정 모드 끄기 (조회 모드)
      } else {
        setSavedBluetooth(null);
        setIsEditing(true); // 값이 없으니까 입력 모드
      }
    } catch (error) {
      console.error("프로필 조회 실패:", error);
    } finally {
      setLoading(false);
    }
  };

  // 2. 등록 버튼 클릭 시
  const handleRegister = async () => {
    try {
      const token = localStorage.getItem("token");
      await axios.patch(
        "https://kmj.shscript.com/api/users/bluetooth",
        { bluetooth: bluetooth }, // body
        { headers: { Authorization: `Bearer ${token}` } }
      );

      alert("저장되었습니다!");
      setSavedBluetooth(bluetooth); // 저장된 상태로 변경
      setIsEditing(false); // 다시 조회 모드로 전환
    } catch (error) {
      console.error("저장 실패:", error);
      alert("저장에 실패했습니다.");
    }
  };

  // 로딩 중일 때
  if (loading) return <div>로딩 중...</div>;

  return (
    <div
      style={{ padding: "20px", border: "1px solid #ddd", borderRadius: "8px" }}
    >
      <h3>📡 블루투스 기기 등록</h3>

      {/* 1. 보기 모드 (View Mode) */}
      {/* 아예 없애지 않고 style로 숨김 처리 */}
      <div
        style={{
          display: !isEditing && savedBluetooth ? "block" : "none",
          marginTop: "10px",
        }}
      >
        <p>
          등록된 기기: <strong>{savedBluetooth}</strong>
        </p>
        <button onClick={() => setIsEditing(true)} style={btnStyle}>
          수정하기
        </button>
      </div>

      {/* 2. 수정/입력 모드 (Edit Mode) */}
      {/* 역시 없애지 않고 style로 숨김 처리. DOM에는 항상 존재함! */}
      <div
        style={{
          display: !isEditing && savedBluetooth ? "none" : "flex",
          marginTop: "10px",
          gap: "10px",
        }}
      >
        <input
          type="text"
          placeholder="MAC 주소를 입력하세요"
          value={bluetooth}
          onChange={(e) => setBluetooth(e.target.value)}
          style={inputStyle}
        />
        <button onClick={handleRegister} style={primaryBtnStyle}>
          {savedBluetooth ? "수정 완료" : "등록"}
        </button>

        {savedBluetooth && (
          <button
            onClick={() => {
              setIsEditing(false);
              setBluetooth(savedBluetooth);
            }}
            style={cancelBtnStyle}
          >
            취소
          </button>
        )}
      </div>
    </div>
  );
};

// 간단한 스타일 (CSS 클래스로 빼셔도 됩니다)
const inputStyle = {
  padding: "8px",
  flex: 1,
  border: "1px solid #ccc",
  borderRadius: "4px",
};
const btnStyle = {
  padding: "8px 16px",
  backgroundColor: "#eee",
  border: "none",
  borderRadius: "4px",
  cursor: "pointer",
};
const primaryBtnStyle = {
  ...btnStyle,
  backgroundColor: "#007bff",
  color: "white",
};
const cancelBtnStyle = {
  ...btnStyle,
  backgroundColor: "#ff4d4f",
  color: "white",
};

export default BluetoothRegister;
