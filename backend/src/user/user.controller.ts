import {
  Controller,
  Get,
  Post,
  Put,
  Patch,
  Delete,
  Body,
  Param,
  UseGuards,
  Request,
} from '@nestjs/common';
import { UserService } from './user.service';
import { User } from './user.entity';
import { AuthGuard } from '@nestjs/passport'; // 이거 import 필수

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get()
  findAll(): Promise<User[]> {
    return this.userService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string): Promise<User> {
    return this.userService.findOne(+id);
  }

  @Post()
  create(@Body() user: Partial<User>): Promise<User> {
    return this.userService.create(user);
  }

  @Put(':id')
  update(@Param('id') id: string, @Body() user: Partial<User>): Promise<User> {
    return this.userService.update(+id, user);
  }

  @Delete(':id')
  remove(@Param('id') id: string): Promise<void> {
    return this.userService.remove(+id);
  }
  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  async getProfile(@Request() req) {
    return this.userService.getProfile(req.user.userId);
  }

  // 2. 블루투스 주소 저장/수정
  @UseGuards(AuthGuard('jwt'))
  @Patch('bluetooth')
  async updateBluetooth(@Request() req, @Body() body: { bluetooth: string }) {
    return this.userService.updateBluetooth(req.user.userId, body.bluetooth);
  }
}
