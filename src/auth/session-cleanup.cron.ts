import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { AuthService } from './auth.service';

@Injectable()
export class SessionCleanupCron implements OnApplicationBootstrap {
  private readonly logger = new Logger(SessionCleanupCron.name);

  constructor(private readonly authService: AuthService) {}

  onApplicationBootstrap() {
    setInterval(async () => {
      try {
        await this.authService.cleanupExpiredSessions();
      } catch (error) {
        this.logger.error('Failed to clean expired sessions', error);
      }
    }, 24 * 60 * 60 * 1000);
  }
}
