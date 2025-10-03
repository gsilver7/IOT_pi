// src/weather/weather.controller.ts
import { Controller, Get, Query, BadRequestException } from '@nestjs/common';
import { WeatherService } from './weather.service';

@Controller('weather')
export class WeatherController {
  constructor(private readonly weatherService: WeatherService) {}

  @Get('forecast')
  async getForecast(
    @Query('date') date: string, // 예: 20251003
    @Query('time') time: string, // 예: 0500
  ) {
    if (!date || !time) {
      throw new BadRequestException('date, time, nx, ny 쿼리 파라미터는 필수입니다.');
    }
    
    // 서비스의 메서드를 호출하여 기상청 API로부터 데이터를 받아옵니다.
    return this.weatherService.getVilageFcst(date, time);
  } // http://192.168.121.179:4000/weather/forecast?date=20251003&time=2300

@Get('now')
async getNowcast() {
  try {
    console.log('getNowcast 요청 받음');
    const result = await this.weatherService.getNowcast();
    console.log('결과:', result);
    return result;
  } catch (error) {
    console.error('getNowcast 에러:', error);
    throw error;
  }
}// http://192.168.121.179:4000/weather/now
}