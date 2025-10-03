// src/weather/weather.service.ts
import { Injectable, InternalServerErrorException, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import { AxiosError } from 'axios';

@Injectable()
export class WeatherService {
  private readonly logger = new Logger(WeatherService.name);
  private readonly KMA_API_KEY: string;

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    // ConfigService를 통해 .env 파일의 API 키를 안전하게 가져옵니다.
    this.KMA_API_KEY = this.configService.get<string>('KMA_API_KEY');
  }

  // 단기예보 정보를 가져오는 메서드
  async getVilageFcst(baseDate: string, baseTime: string) {
    const endpoint = 'http://apis.data.go.kr/1360000/VilageFcstInfoService_2.0/getVilageFcst';
    const params = {
      serviceKey: this.KMA_API_KEY,
      pageNo: '1',
      numOfRows: '1000',
      dataType: 'JSON',
      base_date: baseDate,
      base_time: baseTime,
      nx: '61',
      ny: '127',
    };

    try {
      // HttpService를 이용해 GET 요청을 보냅니다.
      const response = await firstValueFrom(
        this.httpService.get(endpoint, { params }),
      );
      
      // 기상청 API의 자체 에러 코드를 확인합니다.
      const resultCode = response.data.response?.header?.resultCode;
      if (resultCode !== '00') {
        const errorMsg = response.data.response?.header?.resultMsg || 'Unknown API Error';
        throw new InternalServerErrorException(`기상청 API 오류: ${errorMsg}`);
      }

      this.logger.log(`Successfully fetched weather data for date: ${baseDate}`);
      return response.data.response.body.items.item; // 실제 예보 데이터 반환
      
    } catch (error) {
      if (error instanceof AxiosError) {
        this.logger.error(`HTTP Error: ${error.message}`, error.stack);
        throw new InternalServerErrorException('외부 API 요청 중 오류가 발생했습니다.');
      }
      // 기상청 API 자체 에러 또는 기타 에러를 다시 던집니다.
      throw error;
    }
  }
private getApiBaseTime(): { base_date: string; base_time: string } {
  let now = new Date();
  
  // 초단기실황은 매시각 정시 10분 후에 데이터 생성
  // 현재 분이 10분 미만이면 2시간 전 데이터 사용
  if (now.getMinutes() < 10) {
    now.setHours(now.getHours() - 1);
  }
  
  // 정시 기준으로 시간 설정
  now.setMinutes(0);
  now.setSeconds(0);
  
  const base_date =
    now.getFullYear().toString() +
    String(now.getMonth() + 1).padStart(2, '0') +
    String(now.getDate()).padStart(2, '0');
    
  const base_time = String(now.getHours()).padStart(2, '0') + '00';
  
  return { base_date, base_time };
}
async getNowcast() {
  const endpoint = 'http://apis.data.go.kr/1360000/VilageFcstInfoService_2.0/getUltraSrtNcst';

  const { base_date, base_time } = this.getApiBaseTime();

  const params = {
    serviceKey: this.KMA_API_KEY,
    pageNo: '1',
    numOfRows: '1000',
    dataType: 'JSON',
    base_date: base_date,
    base_time: base_time,
    nx: '61',
    ny: '127',
  };

  try {
    const response = await firstValueFrom(
      this.httpService.get(endpoint, { params }),
    );

    // 기상청 API 자체 에러 확인 (getVilageFcst와 동일하게)
    const resultCode = response.data.response?.header?.resultCode;
    if (resultCode !== '00') {
      const errorMsg = response.data.response?.header?.resultMsg || 'Unknown API Error';
      this.logger.error(`기상청 API 오류: ${errorMsg}`);
      throw new InternalServerErrorException(`기상청 API 오류: ${errorMsg}`);
    }

    const rawData = response.data.response.body.items.item;
    this.logger.log(`Successfully fetched nowcast data for ${base_date} ${base_time}`);
    return this.processNowcastData(rawData);

  } catch (error) {
    if (error instanceof AxiosError) {
      this.logger.error(`HTTP Error in getNowcast: ${error.message}`, error.stack);
      throw new InternalServerErrorException('외부 API 요청 중 오류가 발생했습니다.');
    }
    this.logger.error('getNowcast 처리 중 오류:', error);
    throw error;
  }
}  private processNowcastData(rawData: any[]) {
  // 1. 배열을 카테고리별로 쉽게 접근할 수 있는 객체로 변환
  const dataMap = rawData.reduce((acc, item) => {
    acc[item.category] = item.obsrValue;
    return acc;
  }, {});

  // 2. 코드 값을 사람이 이해할 수 있는 텍스트로 변환
  const ptyCode = {
    '0': '없음', '1': '비', '2': '비/눈', '3': '눈',
    '5': '빗방울', '6': '빗방울/눈날림', '7': '눈날림',
  };

  const vecToDirection = (degrees) => {
    const directions = ['북', '북북동', '북동', '동북동', '동', '동남동', '남동', '남남동', '남', '남남서', '남서', '서남서', '서', '서북서', '북서', '북북서'];
    const index = Math.round((degrees % 360) / 22.5);
    return directions[index % 16];
  };

  // 3. 최종적으로 보기 좋은 객체로 조합
  const processed = {
    기준위치: `서울특별시 동대문구 일대 (nx: ${rawData[0].nx}, ny: ${rawData[0].ny})`,
    관측시간: `${rawData[0].baseDate.slice(0, 4)}년 ${rawData[0].baseDate.slice(4, 6)}월 ${rawData[0].baseDate.slice(6, 8)}일 ${rawData[0].baseTime.slice(0, 2)}:00`,
    요약: `현재 기온은 ${dataMap.T1H}℃이며, ${dataMap.PTY === '0' ? '비는 오지 않습니다' : '비 또는 눈이 옵니다'}.`,
    상세정보: {
      기온: `${dataMap.T1H}℃`,
      습도: `${dataMap.REH}%`,
      강수형태: ptyCode[dataMap.PTY] || '정보 없음',
      시간당강수량: `${dataMap.RN1}mm`,
      풍속: `${dataMap.WSD}m/s`,
      풍향: vecToDirection(parseInt(dataMap.VEC)),
    },
  };

  return processed;
}
}