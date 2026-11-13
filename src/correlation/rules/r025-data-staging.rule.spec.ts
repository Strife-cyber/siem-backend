import { DataStagingRule } from './r025-data-staging.rule';
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

function fileHit(
  path: string,
  operation: string,
  hostname = 'srv-file-01',
  index = 0,
): Record<string, unknown> {
  return {
    collected_at: new Date(Date.UTC(2026, 10, 13, 12, 0, index)).toISOString(),
    normalized_at: new Date(Date.UTC(2026, 10, 13, 12, 0, index)).toISOString(),
    source_ip: '10.0.0.5',
    hostname,
    action: 'file_access',
    outcome: 'success',
    source_type: 'linux_auditd',
    file_path: path,
    file_operation: operation,
    raw_message: `type=PATH msg=audit(1763037600.100:4001): item=0 name="${path}" nametype=CREATE`,
  };
}

describe('DataStagingRule', () => {
  const rule = new DataStagingRule();
  const since = new Date(Date.UTC(2026, 10, 13, 11, 0, 0));

  it('fires on a burst of archive creations on one host', async () => {
    const paths = [
      '/tmp/a.zip',
      '/tmp/b.7z',
      '/tmp/c.tar.gz',
      '/tmp/d.rar',
      '/tmp/e.zipx',
      '/tmp/f.tar',
      '/tmp/g.tgz',
    ];
    const hits = paths.map((p, i) => fileHit(p, 'create', 'srv-file-01', i));
    const results: DetectionResult[] = await rule.detect(fakeEs(hits), since);
    expect(results).toHaveLength(1);
    expect(results[0].severity).toBe('HIGH');
    expect(results[0].summary).toContain('srv-file-01');
  });

  it('ignores non-archive file activity and archive deletions', async () => {
    const hits = [
      fileHit('/var/log/app.log', 'create', 'srv-web-01', 0),
      fileHit('/home/deploy/index.html', 'create', 'srv-web-01', 1),
      fileHit('/tmp/old.zip', 'delete', 'srv-web-01', 2),
      fileHit('/tmp/old2.7z', 'delete', 'srv-web-01', 3),
      fileHit('/tmp/old3.rar', 'delete', 'srv-web-01', 4),
      fileHit('/tmp/old4.tar', 'delete', 'srv-web-01', 5),
      fileHit('/tmp/old5.zip', 'delete', 'srv-web-01', 6),
    ];
    const results: DetectionResult[] = await rule.detect(fakeEs(hits), since);
    expect(results).toHaveLength(0);
  });

  it('does not fire below the per-host volume threshold', async () => {
    const hits = [
      fileHit('/tmp/a.zip', 'create', 'srv-file-01', 0),
      fileHit('/tmp/b.7z', 'create', 'srv-file-01', 1),
      fileHit('/tmp/c.tar.gz', 'create', 'srv-file-01', 2),
      fileHit('/tmp/d.rar', 'create', 'srv-file-01', 3),
    ];
    const results: DetectionResult[] = await rule.detect(fakeEs(hits), since);
    expect(results).toHaveLength(0);
  });

  it('does not merge archive counts across different hosts', async () => {
    const hits = [
      fileHit('/tmp/a.zip', 'create', 'srv-one', 0),
      fileHit('/tmp/b.7z', 'create', 'srv-one', 1),
      fileHit('/tmp/c.tar', 'create', 'srv-one', 2),
      fileHit('/tmp/d.rar', 'create', 'srv-two', 3),
      fileHit('/tmp/e.zipx', 'create', 'srv-two', 4),
      fileHit('/tmp/f.tgz', 'create', 'srv-two', 5),
    ];
    const results: DetectionResult[] = await rule.detect(fakeEs(hits), since);
    expect(results).toHaveLength(0);
  });
});
