import { Injectable ,NotFoundException} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  async findAll(): Promise<User[]> {
    return this.userRepository.find();
  }

  async findOne(id: number): Promise<User> {
    return this.userRepository.findOne({ where: { id } });
  }

  async create(user: Partial<User>): Promise<User> {
    const newUser = this.userRepository.create(user);
    return this.userRepository.save(newUser);
  }

  async update(id: number, user: Partial<User>): Promise<User> {
    await this.userRepository.update(id, user);
    return this.findOne(id);
  }

  async remove(id: number): Promise<void> {
    await this.userRepository.delete(id);
  }
  async findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  async validatePassword(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }
  async getProfile(userId: number) {
    return this.userRepository.findOne({
      where: { id: userId },
      select: ['id', 'email', 'name', 'bluetooth'], // 필요한 컬럼만 선택
    });
  }

  // 2. [추가] 블루투스 주소 업데이트
  async updateBluetooth(userId: number, bluetoothAddr: string) {
    // update(조건, 변경할값)
    await this.userRepository.update(userId, { bluetooth: bluetoothAddr });
    return { message: '블루투스 주소가 저장되었습니다.' };
  }
  async updateFaceVector(userId: number, vectorPath: string) {
    // userId에 해당하는 유저의 face 컬럼을 vectorPath로 수정
    await this.userRepository.update(userId, { 
        face: vectorPath 
    });
    
    console.log(`✅ DB Update 완료: User(${userId}) face = ${vectorPath}`);
  }
  async findFaceVectorPath(userId: number): Promise<string> {
    const user = await this.userRepository.findOne({ 
      where: { id: userId },
      select: ['face'] // 다른 정보 필요 없이 face 컬럼만 가져옴 (효율성)
    });

    if (!user) {
      throw new NotFoundException('사용자를 찾을 수 없습니다.');
    }
    
    // face 컬럼이 비어있다면(등록 안 함) null 반환
    return user.face;
  }
}
