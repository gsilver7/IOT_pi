import React, { useState, useEffect } from 'react';
import axios from 'axios';

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

// 2. 컴포넌트 타입을 React.FC (Functional Component)로 지정
const WeatherDisplay: React.FC = () => {
  // 3. useState에 제네릭(<>)으로 타입 지정
  const [weatherData, setWeatherData] = useState<WeatherData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchWeather = async () => {
      try {
        // axios.get 요청 시에도 응답 데이터의 타입을 지정할 수 있음
        const response = await axios.get<WeatherData>('http://192.168.121.179:4000/weather/now');
        setWeatherData(response.data);
        setError(null);
      } catch (err) {
        setError('날씨 정보를 불러오는 데 실패했습니다.');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    fetchWeather();
  }, []);

  if (loading) {
    return <div>날씨 정보를 불러오는 중...</div>;
  }

  if (error) {
    return <div>오류: {error}</div>;
  }

  // weatherData가 null이 아님을 보장하므로, 타입스크립트가 속성을 안전하게 추론
  return (
    <div>
      {weatherData && (
        <>
          <h1>{weatherData.기준위치}</h1>
          <h2>{weatherData.관측시간}</h2>
          <p style={{ fontSize: '1.5rem', fontWeight: 'bold' }}>{weatherData.요약}</p>
          <hr />
          <h3>상세 정보</h3>
          <ul>
            <li><b>기온:</b> {weatherData.상세정보.기온}</li>
            <li><b>습도:</b> {weatherData.상세정보.습도}</li>
            <li><b>풍향:</b> {weatherData.상세정보.풍향}</li>
            <li><b>풍속:</b> {weatherData.상세정보.풍속}</li>
            <li><b>강수형태:</b> {weatherData.상세정보.강수형태}</li>
          </ul>
        </>
      )}
    </div>
  );
};

export default WeatherDisplay;