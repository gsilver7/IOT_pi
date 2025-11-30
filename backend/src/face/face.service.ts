import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../user/user.entity';

@Injectable()
export class FaceService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  async registerFace(userId: number, imageData: string) {
    try {
      // 유저 찾기
      const user = await this.userRepository.findOne({ where: { id: userId } });
      
      if (!user) {
        throw new Error('사용자를 찾을 수 없습니다.');
      }

      // face 칼럼 업데이트 (이미 있으면 덮어쓰기)
      user.face = imageData;
      await this.userRepository.save(user);

      return {
        success: true,
        message: '얼굴이 성공적으로 등록되었습니다.',
      };
    } catch (error) {
      return {
        success: false,
        message: error.message,
      };
    }
  }
}