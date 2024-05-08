import {
  BadRequestException,
  Injectable,
  NotFoundException,
  Post,
} from '@nestjs/common';
import { UsersService } from './users.service';

import { randomBytes, scrypt as _scrypt } from 'crypto';

import { promisify } from 'util';

const scrypt = promisify(_scrypt);

@Injectable()
export class AuthService {
  constructor(private readonly usersService: UsersService) {}

  @Post('')
  async signup(email: string, password: string) {
    const existingUser = await this.usersService.find(email);

    if (existingUser.length) {
      throw new BadRequestException('user already exists');
    }

    // Generate a salt. Returns a string of random numbers and letters in HEX
    const salt = randomBytes(8).toString('hex');
    // Length - 16

    // Password + salt + amount of characters for hash.
    const hash = (await scrypt(password, salt, 32)) as Buffer;

    const hashedPassword = salt + '.' + hash.toString('hex');

    const user = await this.usersService.create(email, hashedPassword);

    return user;
  }

  @Post('')
  async signin(email: string, password: string) {
    const [existingUser] = await this.usersService.find(email);

    if (!existingUser) {
      throw new NotFoundException('user not found');
    }

    const [salt, storedHash] = existingUser.password.split('.');

    const hash = (await scrypt(password, salt, 32)) as Buffer;

    if (hash.toString('hex') !== storedHash) {
      throw new BadRequestException('bad credentials!');
    }

    return existingUser;
  }
}
