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
    @Query('nx') nx: string, // 격자 좌표 X
    @Query('ny') ny: string, // 격자 좌표 Y
  ) {
    if (!date || !time || !nx || !ny) {
      throw new BadRequestException('date, time, nx, ny 쿼리 파라미터는 필수입니다.');
    }
    
    return this.weatherService.getVilageFcst(date, time, nx, ny);
  } // http://192.168.121.179:4000/weather/forecast?date=20251003&time=2300&nx=60&ny=127

  @Get('now')
  async getNowcast(
    @Query('nx') nx: string, // 격자 좌표 X
    @Query('ny') ny: string, // 격자 좌표 Y
  ) {
    if (!nx || !ny) {
      throw new BadRequestException('nx, ny 쿼리 파라미터는 필수입니다.');
    }

    try {
      console.log('getNowcast 요청 받음');
      const result = await this.weatherService.getNowcast(nx, ny);
      console.log('결과:', result);
      return result;
    } catch (error) {
      console.error('getNowcast 에러:', error);
      throw error;
    }
  } // http://192.168.121.179:4000/weather/now?nx=60&ny=127
}