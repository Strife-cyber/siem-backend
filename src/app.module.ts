import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';

import { LogsModule } from './logs/logs.module';
import { ElasticsearchModule } from './elasticsearch/elasticsearch.module';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';
import { RolesGuard } from './auth/guards/roles.guard';
import { BullModule } from '@nestjs/bullmq';
import { DashboardModule } from './dashboard/dashboard.module';
import { IncidentsModule } from './incidents/incidents.module';
import { RulesModule } from './rules/rules.module';
import { SoarModule } from './soar/soar.module';
import { UebaModule } from './ueba/ueba.module';
import { AdminModule } from './admin/admin.module';
import { AuditModule } from './audit/audit.module';
import { ReportsModule } from './reports/reports.module';
import { CorrelationModule } from './correlation/correlation.module';
import { MailModule } from './mail/mail.module';
import { NotificationsModule } from './notifications/notifications.module';
import { RequestLoggerMiddleware } from './common/request-logger.middleware';

@Module({
  imports: [
    PrismaModule,
    ElasticsearchModule,
    AuthModule,
    LogsModule,
    BullModule.forRoot({
      connection: {
        host: process.env.REDIS_HOST || 'localhost',
        port: Number(process.env.REDIS_PORT) || 6379,
      },
    }),
    DashboardModule,
    IncidentsModule,
    RulesModule,
    SoarModule,
    UebaModule,
    AdminModule,
    AuditModule,
    ReportsModule,
    CorrelationModule,
    MailModule,
    NotificationsModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(RequestLoggerMiddleware).forRoutes('*');
  }
}
