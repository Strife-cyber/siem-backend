import {
  DnsTunnelingRule,
  registeredDomain,
  shannonEntropy,
} from './r024-dns-tunneling.rule';
import type { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import type { DetectionResult } from '../interfaces/detection-rule.interface';

function fakeEs(hits: Array<Record<string, unknown>>): ElasticsearchService {
  return {
    getClient: () => ({
      search: jest.fn().mockResolvedValue({
        hits: { hits: hits.map((source) => ({ _source: source })) },
      }),
    }),
  } as unknown as ElasticsearchService;
}

function dnsHit(domain: string, index: number) {
  return {
    collected_at: new Date(Date.UTC(2026, 10, 13, 11, 0, index)).toISOString(),
    normalized_at: new Date(Date.UTC(2026, 10, 13, 11, 0, index)).toISOString(),
    source_ip: '10.0.0.5',
    hostname: 'srv-dns-01',
    action: 'dns_query',
    outcome: 'success',
    source_type: 'linux_syslog',
    domain,
    raw_message: `dnsmasq[1234]: query[A] ${domain} from 10.0.0.5`,
  };
}

function tunnelingLabels(count: number): string[] {
  // Deterministic pseudo-random 60-char labels (valid DNS label length).
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const out: string[] = [];
  let state = 42;
  for (let n = 0; n < count; n++) {
    let label = '';
    for (let i = 0; i < 60; i++) {
      state = (state * 1103515245 + 12345) % 2147483648;
      label += alphabet[state % alphabet.length];
    }
    out.push(label);
  }
  return out;
}

describe('registeredDomain', () => {
  it('keeps unrelated registered domains under a public suffix apart', () => {
    expect(registeredDomain('a.example.co.uk')).toBe('example.co.uk');
    expect(registeredDomain('b.other.co.uk')).toBe('other.co.uk');
    expect(registeredDomain('deep.sub.example.com.au')).toBe('example.com.au');
  });

  it('resolves simple names and strips over-long invalid labels', () => {
    expect(registeredDomain('www.google.com')).toBe('google.com');
    const longLabel = 'x'.repeat(74);
    expect(registeredDomain(`${longLabel}.exfil.evil-corp.com`)).toBe(
      'evil-corp.com',
    );
  });
});

describe('shannonEntropy', () => {
  it('is higher for random-looking names than for dictionary words', () => {
    expect(shannonEntropy('www.google.com')).toBeLessThan(
      shannonEntropy(
        '0v6rast5j284wv98y3umpyo0cu4yyj5ci6vg2g73aj0je4qvzfv8yu58ceps.exfil.evil-corp.com',
      ),
    );
  });
});

describe('DnsTunnelingRule', () => {
  const rule = new DnsTunnelingRule();
  const since = new Date(Date.UTC(2026, 10, 13, 10, 0, 0));

  it('fires on high-volume rotating-label tunneling queries', async () => {
    const labels = tunnelingLabels(32);
    const hits = labels.map((label, i) =>
      dnsHit(`${label}.exfil.evil-corp.com`, i),
    );
    const results: DetectionResult[] = await rule.detect(fakeEs(hits), since);
    expect(results).toHaveLength(1);
    expect(results[0].severity).toBe('HIGH');
    expect(results[0].summary).toContain('evil-corp.com');
  });

  it('does not merge unrelated domains under a public suffix (co.uk)', async () => {
    // 30 queries across 15 different registered .co.uk domains, each with a
    // long first label — naive last-two-labels grouping would see 30 events
    // under "co.uk" and fire; per-registered-domain grouping must not.
    const hits: Array<Record<string, unknown>> = [];
    for (let d = 0; d < 15; d++) {
      for (let i = 0; i < 2; i++) {
        const label = `${'x'.repeat(50)}${d}`;
        hits.push(dnsHit(`${label}.example${d}.co.uk`, hits.length));
      }
    }
    const results: DetectionResult[] = await rule.detect(fakeEs(hits), since);
    expect(results).toHaveLength(0);
  });

  it('does not fire below the volume threshold', async () => {
    const labels = tunnelingLabels(10);
    const hits = labels.map((label, i) =>
      dnsHit(`${label}.exfil.evil-corp.com`, i),
    );
    const results: DetectionResult[] = await rule.detect(fakeEs(hits), since);
    expect(results).toHaveLength(0);
  });
});
