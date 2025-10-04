import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { SerialPort, ReadlineParser } from 'serialport';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { Server } from 'socket.io';

@Injectable()
export class SerialService implements OnModuleInit, OnModuleDestroy {
  private port: SerialPort | null = null;
  private readonly path = '/dev/ttyACM0'; // 아두이노가 연결된 시리얼 포트 경로 (Windows는 COM3 등)
  private readonly baudRate = 9600;
  constructor(private readonly eventEmitter: EventEmitter2) {}

  onModuleInit() {
    this.port = new SerialPort({ path: this.path, baudRate: this.baudRate });
    const parser = this.port.pipe(new ReadlineParser({ delimiter: '\n' }));

    this.port.on('open', () => {
      console.log(`[SerialService] Serial port ${this.path} opened.`);
    });

    parser.on('data', (data: string) => {
      const trimmedData = data.trim();
      console.log(`[SerialService] Received data: ${data.trim()}`);


      try {
        const jsonData = JSON.parse(trimmedData);

        // Check for specific data types using if-else if statements
        if (jsonData.temperature !== undefined) {
          console.log(`[SerialService] 온도 데이터 수신: ${jsonData.temperature}°C`);
          this.eventEmitter.emit('tempdata', {
            type: 'temperature',
            value: jsonData.temperature,
          });
        } else if (jsonData.humidity !== undefined) {
          console.log(`[SerialService] 습도 데이터 수신: ${jsonData.humidity}%`);
          this.eventEmitter.emit('serial.data', {
            type: 'humidity',
            value: jsonData.humidity,
          });
        } else if (jsonData.message !== undefined) {
          console.log(`[SerialService] 메시지 데이터 수신: ${jsonData.message}`);
          this.eventEmitter.emit('serial.data', {
            type: 'message',
            value: jsonData.message,
          });
        } else {
          // If no specific key is found, emit the raw JSON
          console.log('[SerialService] 알 수 없는 형식의 JSON 데이터 수신:', jsonData);
          this.eventEmitter.emit('serial.data', {
            type: 'unknown',
            value: jsonData,
          });
        }

      } catch (e) {
        // If JSON parsing fails, it's a simple string
        console.log('[SerialService] 단순 문자열 데이터 수신:', trimmedData);
        this.eventEmitter.emit('serial.data', {
          type: 'raw',
          value: trimmedData,
          timestamp: new Date().toISOString(),
        });
      }
    });

    this.port.on('error', (err: Error) => {
      console.error(`[SerialService] Error: ${err.message}`);
    });
  }

  onModuleDestroy() {
    if (this.port?.isOpen) {
      this.port.close((err) => {
        if (err) {
          console.error(`[SerialService] Error closing port: ${err.message}`);
        } else {
          console.log(`[SerialService] Serial port ${this.path} closed.`);
        }
      });
    }
  }

  public isPortOpen(): boolean {
    return this.port?.isOpen || false;
  }

  public writeData(data: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.port?.isOpen) {
        return reject(new Error('Serial port is not open.'));
      }
      this.port.write(data, (err) => {
        if (err) {
          reject(err);
        } else {
          console.log(`[SerialService] Sent data: ${data}`);
          resolve();
        }
      });
    });
  }
}