import React, { useState, useEffect, useContext } from "react";
import axios, { AxiosError } from "axios"; // AxiosError 타입을 임포트합니다.
import { GridContext } from "../context/GridContext";

// 1. API 응답 데이터의 타입을 interface로 정의
interface WeatherDetails {
  기온: string;
  습도: string;
  강수형태: string;
  시간당강수량: string;
  풍속: string;
  풍향: string;
}

interface WeatherData {
  기준위치: string;
  관측시간: string;
  요약: string;
  상세정보: WeatherDetails;
}

// GridContext에서 가져올 타입 정의 (예상되는 구조)
interface GridContextType {
  gridCoords: {
    nx: number | null; // nx, ny가 null일 수 있음을 명시
    ny: number | null;
  };
  // 필요한 경우 다른 Context 속성 추가
}

const WeatherDisplay: React.FC = () => {
  // GridContext의 타입을 지정
  const { gridCoords } = useContext(GridContext) as GridContextType;
  const [weatherData, setWeatherData] = useState<WeatherData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchWeather = async () => {
      // 1. 필수 파라미터 유효성 검사 (nx, ny가 null이거나 유효하지 않으면 요청하지 않음)
      if (
        gridCoords.nx === null ||
        gridCoords.ny === null ||
        isNaN(gridCoords.nx) ||
        isNaN(gridCoords.ny)
      ) {
        setError(
          "유효한 좌표(nx, ny) 정보가 없습니다. 지도에서 위치를 선택해주세요."
        );
        setLoading(false);
        return;
      }

      try {
        const response = await axios.get<WeatherData>(
          "https://kmj.shscript.com/api/weather/now", // /api/ 경로가 누락되어 있다면 추가
          {
            params: {
              nx: gridCoords.nx,
              ny: gridCoords.ny,
            },
          }
        );

        // 2. 응답 데이터의 유효성 검사 (데이터 구조가 기대와 다를 때 대비)
        if (!response.data || !response.data.상세정보) {
          setError(
            "서버 응답이 올바른 날씨 데이터 구조를 포함하고 있지 않습니다."
          );
          setWeatherData(null);
          return;
        }

        setWeatherData(response.data);
        setError(null);
      } catch (err) {
        let errorMessage =
          "날씨 정보를 불러오는 데 실패했습니다. (알 수 없는 오류)";

        if (axios.isAxiosError(err)) {
          const axiosError = err as AxiosError;

          if (axiosError.response) {
            // 서버가 응답했으나 2xx 범위가 아님 (400, 500 등)
            errorMessage = `서버 오류: ${axiosError.response.status} ${axiosError.response.statusText}.`;
            // 500 오류 시: 서버 로그를 확인하세요.
          } else if (axiosError.request) {
            // 요청은 갔으나 응답이 없음 (네트워크 에러, 서버 다운 등)
            errorMessage =
              "네트워크 오류: 서버에 연결할 수 없습니다. 서버 상태를 확인하세요.";
          }
        }

        setError(errorMessage);
        console.error("API 요청 실패:", err);
      } finally {
        setLoading(false);
      }
    };

    setLoading(true); // 요청 전에 로딩 상태를 재설정
    fetchWeather();
  }, [gridCoords.nx, gridCoords.ny]); // nx, ny가 변경될 때마다 다시 요청하도록 의존성 배열 수정

  // --- 컴포넌트 랜더링 부분 ---

  // weatherData의 상세 정보를 안전하게 접근하기 위한 변수
  const details = weatherData?.상세정보;

  if (loading) {
    return <div>날씨 정보를 불러오는 중... 🔄</div>;
  }

  if (error) {
    return (
      <div style={{ color: "red", fontWeight: "bold" }}>오류: {error}</div>
    );
  }

  // 데이터가 성공적으로 로드되었으나, 혹시라도 null이면 대비
  if (!weatherData) {
    return <div>날씨 정보를 찾을 수 없습니다.</div>;
  }

  // 랜더링 시 옵셔널 체이닝 및 대체 텍스트 사용
  return (
    <div>
      <h1>{weatherData.기준위치}</h1>
      <h2>{weatherData.관측시간}</h2>
      <p style={{ fontSize: "1.5rem", fontWeight: "bold" }}>
        {weatherData.요약}
      </p>
      <hr />
      <h3>상세 정보</h3>
      <ul>
        <li>
          <b>기온:</b> {details?.기온 || "정보 없음"}
        </li>
        <li>
          <b>습도:</b> {details?.습도 || "정보 없음"}
        </li>
        <li>
          <b>풍향:</b> {details?.풍향 || "정보 없음"}
        </li>
        <li>
          <b>풍속:</b> {details?.풍속 || "정보 없음"}
        </li>
        <li>
          <b>강수형태:</b> {details?.강수형태 || "정보 없음"}
        </li>
        <li>
          <b>시간당 강수량:</b> {details?.시간당강수량 || "정보 없음"}{" "}
          {/* 누락된 속성 추가 */}
        </li>
      </ul>
    </div>
  );
};

export default WeatherDisplay;
