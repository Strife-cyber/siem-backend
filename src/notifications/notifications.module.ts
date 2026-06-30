import { Module, OnModuleInit, Logger } from '@nestjs/common';
import { BullModule, InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { NotificationsProcessor } from './notifications.processor';
import { MailModule } from '../mail/mail.module';

@Module({
  imports: [
    BullModule.registerQueue({
      name: 'notifications',
    }),
    MailModule,
  ],
  providers: [NotificationsProcessor],
})
export class NotificationsModule implements OnModuleInit {
  private readonly logger = new Logger(NotificationsModule.name);

  constructor(
    @InjectQueue('notifications')
    private readonly notificationsQueue: Queue,
  ) {}

  async onModuleInit() {
    // Schedule daily digest at 8 AM every day
    await this.notificationsQueue
      .removeJobScheduler('daily-digest')
      .catch(() => {});
    await this.notificationsQueue.upsertJobScheduler(
      'daily-digest',
      { pattern: '0 8 * * *' },
      {
        name: 'daily-digest',
        data: {},
      },
    );
    this.logger.log('Daily digest scheduled (8:00 AM daily)');
  }
}
