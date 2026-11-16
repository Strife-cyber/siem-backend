import { KerberoastingRule } from './r030-kerberoasting.rule';
import { AsrepRoastingRule } from './r031-asrep-roasting.rule';
import { DcsyncRule } from './r032-dcsync.rule';
import type { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import type { DetectionResult } from '../interfaces/detection-rule.interface';

const T0 = Date.UTC(2026, 10, 16, 12, 0, 0);

function hit(over: Record<string, unknown>): Record<string, unknown> {
  return {
    collected_at: new Date(T0).toISOString(),
    normalized_at: new Date(T0).toISOString(),
    source_ip: '192.168.189.50',
    hostname: 'srv-dc-01',
    source_type: 'windows_security',
    action: 'windows_event',
    outcome: 'success',
    ...over,
  };
}

function kerb4769(spn: string, enc: string, user = 'attacker') {
  return hit({
    event_id: 4769,
    status_code: '0x0',
    spn,
    ticket_encryption_type: enc,
    user_principal: user,
  });
}

function tgt4768(user: string, preauth = 0) {
  return hit({
    event_id: 4768,
    status_code: '0x0',
    preauth_type: preauth,
    user_principal: user,
  });
}

/** Fake ES that answers each search with hits matching the event_id terms. */
function fakeEs(hits: Array<Record<string, unknown>>): ElasticsearchService {
  return {
    getClient: () => ({
      search: jest.fn().mockImplementation((q: any) => {
        const filters: any[] = q.query?.bool?.filter ?? [];
        const termsIds: number[] =
          filters.find((f) => f.terms?.event_id)?.terms?.event_id ?? [];
        const termId = filters.find((f) => f.term?.event_id)?.term?.event_id;
        const ids = termId !== undefined ? [termId] : termsIds;
        const matched = hits.filter(
          (h) => ids.length === 0 || ids.includes(h.event_id as number),
        );
        return Promise.resolve({
          hits: { hits: matched.map((source) => ({ _source: source })) },
        });
      }),
    }),
  } as unknown as ElasticsearchService;
}

describe('KerberoastingRule (R030)', () => {
  const rule = new KerberoastingRule();
  const since = new Date(T0 - 60_000);

  it('fires HIGH on 3 distinct RC4 service tickets from one IP/user', async () => {
    const hits = [
      kerb4769('MSSQLSvc/sql01.corp.local', '0x17'),
      kerb4769('HTTP/web01.corp.local', '0x17'),
      kerb4769('ldap/dc02.corp.local', '0x1'),
    ];
    const results: DetectionResult[] = await rule.detect(fakeEs(hits), since);
    expect(results).toHaveLength(1);
    expect(results[0].severity).toBe('HIGH');
    expect(results[0].related_entities?.ips).toEqual(['192.168.189.50']);
    expect(results[0].related_entities?.hosts).toEqual([]);
  });

  it('fires CRITICAL on any canary (honey) account request', async () => {
    process.env.AD_HONEY_ACCOUNTS = 'svc_backup$canary';
    try {
      const hits = [kerb4769('svc_backup$canary', '0x12')];
      const results = await rule.detect(fakeEs(hits), since);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe('CRITICAL');
    } finally {
      delete process.env.AD_HONEY_ACCOUNTS;
    }
  });

  it('ignores machine accounts, krbtgt and failed requests', async () => {
    const hits = [
      kerb4769('HOST/ws01$', '0x17'),
      kerb4769('krbtgt', '0x17'),
      { ...kerb4769('MSSQLSvc/a', '0x17'), status_code: '0x8' },
    ];
    const results = await rule.detect(fakeEs(hits), since);
    expect(results).toHaveLength(0);
  });

  it('does not fire on AES-only tickets below the SPN threshold', async () => {
    const hits = [kerb4769('MSSQLSvc/a', '0x12'), kerb4769('HTTP/b', '0x12')];
    const results = await rule.detect(fakeEs(hits), since);
    expect(results).toHaveLength(0);
  });

  it('honours AD_RC4_ALLOWED_SERVICES allowlist', async () => {
    process.env.AD_RC4_ALLOWED_SERVICES = 'MSSQLSvc/sql01.corp.local';
    try {
      const hits = [
        kerb4769('MSSQLSvc/sql01.corp.local', '0x17'),
        kerb4769('MSSQLSvc/sql01.corp.local', '0x17'),
        kerb4769('MSSQLSvc/sql01.corp.local', '0x17'),
      ];
      const results = await rule.detect(fakeEs(hits), since);
      expect(results).toHaveLength(0);
    } finally {
      delete process.env.AD_RC4_ALLOWED_SERVICES;
    }
  });
});

describe('AsrepRoastingRule (R031)', () => {
  const rule = new AsrepRoastingRule();
  const since = new Date(T0 - 60_000);

  it('fires HIGH on a single pre-auth-disabled TGT request', async () => {
    const results = await rule.detect(fakeEs([tgt4768('roastable1')]), since);
    expect(results).toHaveLength(1);
    expect(results[0].severity).toBe('HIGH');
  });

  it('fires CRITICAL on a sweep of 3 accounts from one IP', async () => {
    const hits = [tgt4768('acct1'), tgt4768('acct2'), tgt4768('acct3')];
    const results = await rule.detect(fakeEs(hits), since);
    expect(results).toHaveLength(1);
    expect(results[0].severity).toBe('CRITICAL');
    expect(results[0].summary).toContain('sweep');
  });

  it('ignores pre-authenticated, machine and allowlisted accounts', async () => {
    process.env.AD_NOPREAUTH_ALLOWED = 'legacy_svc';
    try {
      const hits = [
        tgt4768('normal_user', 2),
        tgt4768('HOST/dc01$', 0),
        tgt4768('legacy_svc', 0),
      ];
      const results = await rule.detect(fakeEs(hits), since);
      expect(results).toHaveLength(0);
    } finally {
      delete process.env.AD_NOPREAUTH_ALLOWED;
    }
  });
});

describe('DcsyncRule (R032)', () => {
  const rule = new DcsyncRule();
  const since = new Date(T0 - 60_000);

  const dcsync4662 = hit({
    event_id: 4662,
    status_code: '0x0',
    subject_user_name: 'attacker',
    user_principal: 'attacker',
    logon_id: '0x3e7',
    replication_right: true,
  });
  const logon4624 = hit({
    event_id: 4624,
    logon_id: '0x3e7',
    source_ip: '192.168.189.50',
  });

  it('fires CRITICAL and resolves the attacker IP via the 4624 logon join', async () => {
    const results = await rule.detect(fakeEs([dcsync4662, logon4624]), since);
    expect(results).toHaveLength(1);
    expect(results[0].severity).toBe('CRITICAL');
    expect(results[0].related_entities?.ips).toEqual(['192.168.189.50']);
    expect(results[0].related_entities?.hosts).toEqual([]);
  });

  it('ignores a 4624 from a different DC sharing the same logon ID', async () => {
    // Windows logon IDs are computer-local: DC02 also has a 0x3e7 session.
    const otherDc4624 = hit({
      event_id: 4624,
      logon_id: '0x3e7',
      hostname: 'srv-dc-02',
      source_ip: '192.168.189.99',
    });
    const results = await rule.detect(
      fakeEs([dcsync4662, otherDc4624]),
      since,
    );
    expect(results).toHaveLength(1);
    expect(results[0].severity).toBe('CRITICAL');
    expect(results[0].related_entities?.ips).toEqual([]);
    expect(results[0].summary).toContain('manual containment');
  });

  it('prefers the 4624 from the same DC when logon IDs collide', async () => {
    const otherDc4624 = hit({
      event_id: 4624,
      logon_id: '0x3e7',
      hostname: 'srv-dc-02',
      source_ip: '192.168.189.99',
    });
    const results = await rule.detect(
      fakeEs([dcsync4662, otherDc4624, logon4624]),
      since,
    );
    expect(results).toHaveLength(1);
    expect(results[0].related_entities?.ips).toEqual(['192.168.189.50']);
  });

  it('fires CRITICAL with unresolved IP when no matching logon exists', async () => {
    const results = await rule.detect(fakeEs([dcsync4662]), since);
    expect(results).toHaveLength(1);
    expect(results[0].severity).toBe('CRITICAL');
    expect(results[0].related_entities?.ips).toEqual([]);
    expect(results[0].summary).toContain('manual containment');
  });

  it('ignores machine accounts and non-replication access', async () => {
    const hits = [
      { ...dcsync4662, subject_user_name: 'SRV-DC01$' },
      {
        ...dcsync4662,
        subject_user_name: 'backup_svc',
        replication_right: false,
      },
      { ...dcsync4662, subject_user_name: 'svc', status_code: '0x1' },
    ];
    const results = await rule.detect(fakeEs(hits), since);
    expect(results).toHaveLength(0);
  });
});
