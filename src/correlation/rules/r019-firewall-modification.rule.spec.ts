import type { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import { FirewallModificationRule } from './r019-firewall-modification.rule';

function makeEs(hits: unknown[]): ElasticsearchService {
  return {
    getClient: () => ({
      search: jest.fn().mockResolvedValue({ hits: { hits } }),
    }),
  } as unknown as ElasticsearchService;
}

function hit(overrides: Record<string, unknown> = {}) {
  return {
    _source: {
      collected_at: '2026-11-13T13:00:00.000Z',
      source_ip: '10.0.0.5',
      hostname: 'WIN-DC-09',
      user_principal: 'SYSTEM',
      action: 'firewall_rule_change',
      outcome: 'success',
      source_type: 'windows_network',
      raw_message: '<Event><System><EventID>2004</EventID></System></Event>',
      ...overrides,
    },
  };
}

describe('FirewallModificationRule (R019)', () => {
  const rule = new FirewallModificationRule();
  const since = new Date('2026-11-13T12:00:00.000Z');

  it('has the expected definition', () => {
    expect(rule.id).toBe('R019');
    expect(rule.definition.source_types).toEqual(['windows_network']);
    expect(rule.definition.actions).toEqual(['firewall_rule_change']);
    expect(rule.definition.threshold).toBe(1);
  });

  it('fires WARNING when a firewall rule change is present', async () => {
    const results = await rule.detect(makeEs([hit()]), since);
    expect(results).toHaveLength(1);
    expect(results[0].severity).toBe('WARNING');
    expect(results[0].summary).toContain('added');
    expect(results[0].related_entities.hosts).toContain('WIN-DC-09');
  });

  it('does not fire without firewall_rule_change events', async () => {
    const results = await rule.detect(makeEs([]), since);
    expect(results).toHaveLength(0);
  });

  it('summarizes mixed change kinds without duplicates', async () => {
    const results = await rule.detect(
      makeEs([
        hit({
          raw_message:
            '<Event><System><EventID>2004</EventID></System></Event>',
        }),
        hit({
          raw_message:
            '<Event><System><EventID>2006</EventID></System></Event>',
        }),
        hit({
          raw_message:
            '<Event><System><EventID>2004</EventID></System></Event>',
        }),
      ]),
      since,
    );
    expect(results[0].summary).toContain('added');
    expect(results[0].summary).toContain('deleted');
    expect(results[0].summary.match(/added/g)).toHaveLength(1);
  });

  it('falls back to "changed" for unknown event IDs', async () => {
    const results = await rule.detect(
      makeEs([
        hit({
          raw_message:
            '<Event><System><EventID>2099</EventID></System></Event>',
        }),
      ]),
      since,
    );
    expect(results[0].summary).toContain('changed');
  });
});
