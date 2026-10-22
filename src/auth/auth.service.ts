import {
  Injectable,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import * as crypto from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async register(dto: RegisterDto, userAgent?: string, ip?: string) {
    const { email, password, firstName, lastName } = dto;
    const existing = await this.prisma.user.findUnique({ where: { email } });
    if (existing) {
      throw new ConflictException('Email already registered');
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await this.prisma.user.create({
      data: {
        email,
        password: passwordHash,
        firstName,
        lastName,
      },
    });
    const access_token = await this.generateAccessToken(user);
    const refresh_token = await this.generateRefreshToken(user.id, userAgent, ip);
    return {
      access_token,
      refresh_token,
      user: { id: user.id, email: user.email, role: user.role },
    };
  }

  async login(dto: LoginDto, userAgent?: string, ip?: string) {
    const { email, password } = dto;
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const passwordValid = await bcrypt.compare(password, user.password);
    if (!passwordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const access_token = await this.generateAccessToken(user);
    const refresh_token = await this.generateRefreshToken(user.id, userAgent, ip);
    return {
      access_token,
      refresh_token,
      user: { id: user.id, email: user.email, role: user.role },
    };
  }

  private async generateAccessToken(user: any) {
    const payload = { sub: user.id, email: user.email, role: user.role };
    return this.jwtService.signAsync(payload, { expiresIn: '15m' });
  }

  private async generateRefreshToken(userId: string, userAgent?: string, ip?: string, familyId?: string) {
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const famId = familyId || crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await this.prisma.session.create({
      data: {
        userId,
        tokenHash,
        familyId: famId,
        userAgent,
        ip,
        expiresAt,
      },
    });

    return rawToken;
  }

  async refresh(rawToken: string, userAgent?: string, ip?: string) {
    if (!rawToken) {
      throw new UnauthorizedException('Refresh token missing');
    }
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const session = await this.prisma.session.findUnique({ where: { tokenHash } });

    if (!session) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (session.revokedAt || session.expiresAt < new Date()) {
      await this.prisma.session.updateMany({
        where: { familyId: session.familyId },
        data: { revokedAt: new Date() },
      });
      throw new UnauthorizedException('Refresh token reuse detected. Session revoked.');
    }

    await this.prisma.session.update({
      where: { id: session.id },
      data: { revokedAt: new Date() },
    });

    const user = await this.prisma.user.findUnique({ where: { id: session.userId } });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const access_token = await this.generateAccessToken(user);
    const new_refresh_token = await this.generateRefreshToken(user.id, userAgent, ip, session.familyId);

    return {
      access_token,
      refresh_token: new_refresh_token,
      user: { id: user.id, email: user.email, role: user.role },
    };
  }

  async logout(rawToken: string) {
    if (!rawToken) return;
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    await this.prisma.session.updateMany({
      where: { tokenHash },
      data: { revokedAt: new Date() },
    });
  }

  async cleanupExpiredSessions() {
    const now = new Date();
    await this.prisma.session.deleteMany({
      where: {
        OR: [
          { expiresAt: { lt: now } },
          { revokedAt: { not: null } },
        ],
      },
    });
  }
}
