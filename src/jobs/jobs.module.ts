import { Global, Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { EmailModule } from '../email/email.module';
import { LoggingModule } from '../logging/logging.module';
import { NotificationProcessor } from './processors/notification.processor';
import { NotificationWorker } from './workers/notification.worker';
import { NotificationQueueService } from './services/notification-queue.service';
import { SessionCleanupService } from './services/session-cleanup.service';

@Global()
@Module({
  imports: [
    ConfigModule, // Provides ConfigService to our queue/worker services
    EmailModule,
    LoggingModule,
  ],
  providers: [
    NotificationProcessor,
    NotificationQueueService,
    NotificationWorker,
    SessionCleanupService,
  ],
  exports: [NotificationQueueService],
})
export class JobsModule {}

