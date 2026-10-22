import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { LoggingService } from '../../logging/logging.service';

@Injectable()
export class SessionCleanupCron implements OnModuleInit, OnModuleDestroy {
  private intervalTimer: NodeJS.Timeout | null = null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly logger: LoggingService,
  ) {}

  onModuleInit() {
    // Run once a day (24 hours)
    const twentyFourHours = 24 * 60 * 60 * 1000;
    this.intervalTimer = setInterval(() => {
      this.handleExpiredSessionsCleanup();
    }, twentyFourHours);
  }

  onModuleDestroy() {
    if (this.intervalTimer) {
      clearInterval(this.intervalTimer);
      this.intervalTimer = null;
    }
  }

  async handleExpiredSessionsCleanup() {
    try {
      const result = await this.prisma.session.deleteMany({
        where: {
          OR: [
            { expiresAt: { lt: new Date() } },
            { revokedAt: { not: null } },
          ],
        },
      });
      await this.logger.log({
        level: 'INFO',
        action: 'CLEANUP_SESSIONS',
        message: `Cleaned up ${result.count} expired or revoked sessions`,
      });
    } catch (error) {
      await this.logger.log({
        level: 'ERROR',
        action: 'CLEANUP_SESSIONS_FAILED',
        message: 'Failed to clean up expired sessions',
        metadata: { error: error instanceof Error ? error.stack : String(error) },
      });
    }
  }
}
