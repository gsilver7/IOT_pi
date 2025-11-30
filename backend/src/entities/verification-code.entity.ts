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

  @Column() // unique: true 제거
  email: string;

  @Column()
  code: string;

  @Column()
  expiresAt: Date;

  @Column({ default: false })
  isUsed: boolean;

  @CreateDateColumn()
  createdAt: Date;
}
