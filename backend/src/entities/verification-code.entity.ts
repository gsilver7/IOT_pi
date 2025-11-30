import {
  Column,
  Entity,
  PrimaryGeneratedColumn,
  CreateDateColumn,
} from 'typeorm';

@Entity()
export class VerificationCode {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  code: string; // 6자리 인증 코드

  @Column()
  expiresAt: Date; // 코드 만료 시각

  @Column({ default: false })
  isUsed: boolean; // 코드 사용 여부

  @CreateDateColumn()
  createdAt: Date;
}
