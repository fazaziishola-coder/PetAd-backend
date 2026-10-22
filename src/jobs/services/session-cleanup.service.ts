import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class SessionCleanupService implements OnApplicationBootstrap {
  private readonly logger = new Logger(SessionCleanupService.name);

  constructor(private readonly prisma: PrismaService) {}

  onApplicationBootstrap() {
    // Run cleanup on startup and periodically
    this.handleExpiredSessionsCleanup();
    setInterval(() => {
      this.handleExpiredSessionsCleanup();
    }, 24 * 60 * 60 * 1000);
  }

  async handleExpiredSessionsCleanup() {
    this.logger.log('Running scheduled expired sessions cleanup...');
    try {
      const result = await this.prisma.session.deleteMany({
        where: {
          OR: [
            { expiresAt: { lt: new Date() } },
            { revokedAt: { not: null } },
          ],
        },
      });
      this.logger.log(`Cleaned up ${result.count} expired or revoked sessions.`);
    } catch (error) {
      this.logger.error('Failed to clean up expired sessions', error);
    }
  }
}
