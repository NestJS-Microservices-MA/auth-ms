import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';

import { RegisterDto, LoginDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
    private readonly logger = new Logger('AuthService');

    constructor(private readonly jwtService: JwtService) {
        super();
    }

    onModuleInit() {
        this.$connect();
        this.logger.log('Connected to the MongoDB database');
    }

    async signJWT(payload: JwtPayload) {
        return this.jwtService.sign(payload);
    }

    async registerUser(registerDto: RegisterDto) {
        const { name, email, password } = registerDto;
        try {
            const user = await this.user.findUnique({
                where: {
                    email,
                },
            });

            if (user) {
                throw new RpcException({
                    status: HttpStatus.BAD_REQUEST,
                    message: 'User already exists',
                });
            }

            const newUser = await this.user.create({
                data: {
                    name,
                    email,
                    password: bcrypt.hashSync(password, 10),
                },
            });

            const { password: _, ...userWithoutPassword } = newUser;

            return {
                user: userWithoutPassword,
                token: await this.signJWT(userWithoutPassword),
            };
        } catch (error) {
            throw new RpcException({
                status: HttpStatus.BAD_REQUEST,
                message: error.message,
            });
        }
    }

    async loginUser(loginDto: LoginDto) {
        const { email, password } = loginDto;
        try {
            const user = await this.user.findUnique({
                where: {
                    email,
                },
            });

            if (!user) {
                throw new RpcException({
                    status: HttpStatus.BAD_REQUEST,
                    message: 'Email/Password invalid',
                });
            }

            const isPasswordValid = bcrypt.compareSync(password, user.password);

            if (!isPasswordValid) {
                throw new RpcException({
                    status: HttpStatus.BAD_REQUEST,
                    message: 'Email/Password invalid',
                });
            }

            const { password: _, ...userWithoutPassword } = user;

            return {
                user: userWithoutPassword,
                token: await this.signJWT(userWithoutPassword),
            };
        } catch (error) {
            throw new RpcException({
                status: HttpStatus.BAD_REQUEST,
                message: error.message,
            });
        }
    }

    async verifyToken(token: string) {
        try {
            const { sub, iat, exp, ...user } = await this.jwtService.verify(token, {
                secret: envs.jwtSecret
            });

            return {
                user,
                token: await this.signJWT(user),
            }
        } catch (error) {
            throw new RpcException({
                status: HttpStatus.UNAUTHORIZED,
                message: 'Invalid token',
            });
        }
        return token;
    }
}
