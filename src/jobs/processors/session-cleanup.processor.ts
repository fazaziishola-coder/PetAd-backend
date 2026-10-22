import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class SessionCleanupProcessor {
  private readonly logger = new Logger(SessionCleanupProcessor.name);

  constructor(private readonly prisma: PrismaService) {}

  async handleExpiredSessionsCleanup() {
    this.logger.log('Starting scheduled cleanup of expired/revoked sessions...');
    try {
      const result = await this.prisma.session.deleteMany({
        where: {
          OR: [
            { expiresAt: { lt: new Date() } },
            { revokedAt: { not: null } },
          ],
        },
      });
      this.logger.log(`Successfully cleaned up ${result.count} expired or revoked sessions.`);
    } catch (error) {
      this.logger.error('Failed to clean up expired sessions', error);
    }
  }
}
