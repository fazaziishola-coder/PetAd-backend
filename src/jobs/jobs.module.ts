import { Global, Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { EmailModule } from '../email/email.module';
import { LoggingModule } from '../logging/logging.module';
import { NotificationProcessor } from './processors/notification.processor';
import { NotificationWorker } from './workers/notification.worker';
import { NotificationQueueService } from './services/notification-queue.service';
import { SessionCleanupCron } from './cron/session-cleanup.cron';


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
    SessionCleanupCron,

  ],
  exports: [NotificationQueueService],
})
export class JobsModule {}

