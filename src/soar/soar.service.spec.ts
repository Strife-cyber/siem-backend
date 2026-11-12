import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { SoarService } from './soar.service';
import { PrismaService } from '../prisma/prisma.service';
import { FIREWALL_AGENT } from './agents/firewall-agent.interface';
import type { IFirewallAgent } from './agents/firewall-agent.interface';

describe('SoarService', () => {
  let service: SoarService;
  let prisma: {
    incident: { findUnique: jest.Mock; update: jest.Mock };
    playbookExecution: {
      create: jest.Mock;
      update: jest.Mock;
      findUnique: jest.Mock;
      findFirst: jest.Mock;
    };
    soarAction: {
      create: jest.Mock;
      findMany: jest.Mock;
      findUnique: jest.Mock;
      update: jest.Mock;
    };
  };

  // Plain jest.fn() mocks so assertions don't trip no-unbound-method
  const agentFns = {
    blockIp: jest.fn(),
    blockPort: jest.fn(),
    isolateHost: jest.fn(),
    unIsolateHost: jest.fn(),
    checkIp: jest.fn(),
    unblockIp: jest.fn(),
    listRules: jest.fn(),
    deleteRule: jest.fn(),
    healthCheck: jest.fn(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    agentFns.blockIp.mockResolvedValue({ success: true });
    agentFns.blockPort.mockResolvedValue({ success: true });
    agentFns.isolateHost.mockResolvedValue({ success: true });
    agentFns.unIsolateHost.mockResolvedValue({ success: true });
    agentFns.checkIp.mockResolvedValue({ blocked: false, rules: [] });
    agentFns.unblockIp.mockResolvedValue({ success: true });

    const agent = {
      provider: 'pfsense',
      isConfigured: true,
      ...agentFns,
    } as unknown as IFirewallAgent;

    prisma = {
      incident: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'inc-1',
          related_entities: { ips: ['10.0.0.1'], hosts: [], users: [] },
        }),
        update: jest.fn().mockResolvedValue({}),
      },
      playbookExecution: {
        create: jest.fn().mockResolvedValue({ id: 'exec-1' }),
        update: jest.fn().mockResolvedValue({}),
        findUnique: jest.fn(),
        findFirst: jest.fn(),
      },
      soarAction: {
        create: jest.fn().mockResolvedValue({}),
        findMany: jest.fn(),
        findUnique: jest.fn(),
        update: jest.fn(),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SoarService,
        { provide: PrismaService, useValue: prisma },
        { provide: FIREWALL_AGENT, useValue: agent },
      ],
    }).compile();

    service = module.get<SoarService>(SoarService);
  });

  describe('executePlaybook (AUTO)', () => {
    it('returns EXECUTED and records actions when the playbook succeeds', async () => {
      const result = await service.executePlaybook({
        incident_id: 'inc-1',
        playbook_name: 'block_ip',
        mode: 'AUTO',
      });

      expect(result.status).toBe('EXECUTED');
      expect(prisma.playbookExecution.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ status: 'EXECUTED' }),
        }),
      );
      expect(prisma.soarAction.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            action_type: 'block_ip',
            target: '10.0.0.1',
            incident_id: 'inc-1',
            execution_id: 'exec-1',
          }),
        }),
      );
    });

    it('returns FAILED (not EXECUTED) for an unknown playbook', async () => {
      const result = await service.executePlaybook({
        incident_id: 'inc-1',
        playbook_name: 'does_not_exist',
        mode: 'AUTO',
      });

      expect(result.status).toBe('FAILED');
      expect(prisma.playbookExecution.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ status: 'FAILED' }),
        }),
      );
    });

    it('returns FAILED when the playbook run throws', async () => {
      prisma.incident.findUnique
        .mockReset()
        .mockResolvedValueOnce({ id: 'inc-1' })
        .mockRejectedValueOnce(new Error('db down'));

      const result = await service.executePlaybook({
        incident_id: 'inc-1',
        playbook_name: 'block_ip',
        mode: 'AUTO',
      });

      expect(result.status).toBe('FAILED');
      expect(prisma.playbookExecution.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            status: 'FAILED',
            result_payload: { error: 'db down' },
          }),
        }),
      );
    });
  });

  describe('executePlaybook (CONFIRM)', () => {
    it('persists params on the execution so approval can replay them', async () => {
      const result = await service.executePlaybook({
        incident_id: 'inc-1',
        playbook_name: 'block_port',
        mode: 'CONFIRM',
        params: { ip: '10.0.0.2', port: 22, protocol: 'tcp' },
      });

      expect(result.status).toBe('PENDING');
      expect(prisma.playbookExecution.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            result_payload: {
              params: { ip: '10.0.0.2', port: 22, protocol: 'tcp' },
            },
          }),
        }),
      );
      // The playbook must NOT run before approval
      expect(agentFns.blockPort).not.toHaveBeenCalled();
    });
  });

  describe('approveExecution', () => {
    it('replays the params persisted at creation time', async () => {
      prisma.playbookExecution.findUnique.mockResolvedValue({
        id: 'exec-2',
        status: 'PENDING',
        mode: 'CONFIRM',
        playbook_name: 'block_port',
        incident_id: 'inc-1',
        result_payload: {
          params: { ip: '10.0.0.2', port: 22, protocol: 'tcp', reason: 'test' },
        },
      });
      prisma.incident.findUnique.mockResolvedValue({
        related_entities: {},
      });

      const result = await service.approveExecution('exec-2');

      expect(result.status).toBe('EXECUTED');
      expect(agentFns.blockPort).toHaveBeenCalledWith(
        '10.0.0.2',
        22,
        'tcp',
        'test',
      );
      expect(prisma.playbookExecution.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ status: 'EXECUTED' }),
        }),
      );
    });

    it('rejects with 400 when the execution is not PENDING', async () => {
      prisma.playbookExecution.findUnique.mockResolvedValue({
        id: 'exec-3',
        status: 'EXECUTED',
        mode: 'CONFIRM',
        playbook_name: 'block_ip',
        incident_id: 'inc-1',
        result_payload: null,
      });

      await expect(service.approveExecution('exec-3')).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('undoAction', () => {
    it('unblocks the IP and marks the action REVERTED', async () => {
      prisma.soarAction.findUnique.mockResolvedValue({
        id: 'act-1',
        incident_id: 'inc-1',
        action_type: 'block_ip',
        target: '10.0.0.1',
        status: 'EXECUTED',
        provider: 'pfsense',
      });

      const result = await service.undoAction('act-1');

      expect(result.status).toBe('REVERTED');
      expect(agentFns.unblockIp).toHaveBeenCalledWith('10.0.0.1');
      expect(prisma.soarAction.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ status: 'REVERTED' }),
        }),
      );
    });

    it('throws 404 for an unknown action', async () => {
      prisma.soarAction.findUnique.mockResolvedValue(null);

      await expect(service.undoAction('missing')).rejects.toThrow(
        'SOAR action not found',
      );
    });
  });
});
