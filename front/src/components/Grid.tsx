import React, { useState, useEffect } from 'react';

// 기상청 격자 좌표 변환 공식 (TypeScript 버전)
const RE = 6371.00877; // 지구 반경(km)
const GRID = 5.0; // 격자 간격(km)
const SLAT1 = 30.0; // 표준 위도 1
const SLAT2 = 60.0; // 표준 위도 2
const OLON = 126.0; // 기준점 경도
const OLAT = 38.0; // 기준점 위도
const XO = 43; // 기준점 X좌표
const YO = 136; // 기준점 Y좌표

interface GridCoords {
    nx: number;
    ny: number;
}

interface GeolocationCoords {
    latitude: number;
    longitude: number;
}

function convertToGrid(lat: number, lon: number): GridCoords {
    const DEGRAD = Math.PI / 180.0;

    const re = RE / GRID;
    const slat1 = SLAT1 * DEGRAD;
    const slat2 = SLAT2 * DEGRAD;
    const olon = OLON * DEGRAD;
    const olat = OLAT * DEGRAD;

    let sn = Math.tan(Math.PI * 0.25 + slat2 * 0.5) / Math.tan(Math.PI * 0.25 + slat1 * 0.5);
    sn = Math.log(Math.cos(slat1) / Math.cos(slat2)) / Math.log(sn);
    let sf = Math.tan(Math.PI * 0.25 + slat1 * 0.5);
    sf = Math.pow(sf, sn) * Math.cos(slat1) / sn;
    let ro = Math.tan(Math.PI * 0.25 + olat * 0.5);
    ro = re * sf / Math.pow(ro, sn);

    let ra = Math.tan(Math.PI * 0.25 + lat * DEGRAD * 0.5);
    ra = re * sf / Math.pow(ra, sn);
    let theta = lon * DEGRAD - olon;
    if (theta > Math.PI) theta -= 2.0 * Math.PI;
    if (theta < -Math.PI) theta += 2.0 * Math.PI;

    const x = Math.floor(ra * Math.sin(theta)) + XO;
    const y = Math.floor(ro - ra * Math.cos(theta)) + YO;

    return { nx: x, ny: y };
}

const Grid: React.FC = () => {
    const [geoCoords, setGeoCoords] = useState<GeolocationCoords | null>(null);
    const [gridCoords, setGridCoords] = useState<GridCoords | null>(null);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        if (!navigator.geolocation) {
            setError('Geolocation API를 지원하지 않는 브라우저입니다.');
            return;
        }

        navigator.geolocation.getCurrentPosition(
            (position) => {
                const { latitude, longitude } = position.coords;
                
                // 위도와 경도 상태 업데이트
                setGeoCoords({ latitude, longitude });

                // 변환된 격자 좌표 상태 업데이트
                const coords = convertToGrid(latitude, longitude);
                setGridCoords(coords);
            },
            (err) => {
                let errorMessage: string;
                switch (err.code) {
                    case err.PERMISSION_DENIED:
                        errorMessage = '사용자가 위치 정보 요청을 거부했습니다.';
                        break;
                    case err.POSITION_UNAVAILABLE:
                        errorMessage = '위치 정보를 사용할 수 없습니다.';
                        break;
                    case err.TIMEOUT:
                        errorMessage = '위치 정보를 가져오는 데 시간이 초과되었습니다.';
                        break;
                    default:
                        errorMessage = '알 수 없는 오류가 발생했습니다.';
                        break;
                }
                setError(errorMessage);
            }
        );
    }, []);

    if (error) {
        return <div style={{ color: 'red' }}>오류: {error}</div>;
    }

    if (!gridCoords) {
        return <div>위치 정보를 가져오는 중...</div>;
    }

    return (
        <div>
            <h2>현재 위치 정보</h2>
            {geoCoords && (
                <>
                    <p><strong>위도 (Latitude):</strong> {geoCoords.latitude}</p>
                    <p><strong>경도 (Longitude):</strong> {geoCoords.longitude}</p>
                </>
            )}
            
            <hr />

            <h2>기상청 격자 좌표</h2>
            <p><strong>X 좌표 (nx):</strong> {gridCoords.nx}</p>
            <p><strong>Y 좌표 (ny):</strong> {gridCoords.ny}</p>
        </div>
    );
};

export default Grid;