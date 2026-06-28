/**
 * Synthetic 30-day log generator for the Smart SIEM UEBA demo.
 *
 * Generates realistic-looking logs for CTU characters:
 * - Jack Bauer: Normal analyst, early morning, consistent
 * - Chloe O'Brian: Normal analyst, standard hours, tech-heavy
 * - Nina Myers: Normal analyst (most days) but with hidden exfiltration pattern
 * - Bill Buchanan: Director, light activity, meetings
 * - Tony Almeida: Normal analyst, standard hours
 * - Michelle Dessler: Normal analyst
 * - David Palmer: External VIP, very light activity
 *
 * Usage:
 *   npx tsx scripts/generate-synthetic-logs.ts
 *
 * This will POST logs to the API or output as JSON.
 * Set API_URL env var to target a running backend.
 * Without API_URL, outputs to stdout as NDJSON.
 */

const CTU_USERS = [
  { principal: 'CTU\\jack.bauer', display: 'Jack Bauer', role: 'analyst' },
  { principal: 'CTU\\chloe.obrian', display: "Chloe O'Brian", role: 'analyst' },
  { principal: 'CTU\\nina.myers', display: 'Nina Myers', role: 'analyst' },
  { principal: 'CTU\\tony.almeida', display: 'Tony Almeida', role: 'analyst' },
  {
    principal: 'CTU\\michelle.dessler',
    display: 'Michelle Dessler',
    role: 'analyst',
  },
  {
    principal: 'CTU\\bill.buchanan',
    display: 'Bill Buchanan',
    role: 'director',
  },
  { principal: 'CTU\\david.palmer', display: 'David Palmer', role: 'vip' },
];

const HOSTS = [
  'CTU-DESK-01',
  'CTU-DESK-02',
  'CTU-DESK-03',
  'CTU-DESK-04',
  'CTU-SRV-01',
  'CTU-SRV-02',
  'CTU-LAP-01',
];
const SOURCE_TYPES = [
  'windows_security',
  'linux_auth',
  'firewall',
  'syslog',
  'web_proxy',
];
const ACTIONS = [
  'login',
  'logout',
  'file_access',
  'file_download',
  'file_upload',
  'process_start',
  'network_connect',
];
const TAXONOMIES = ['T1078', 'T1059', 'T1083', 'T1105', 'T1041', 'T1003'];

/**
 * Generate a full 30-day synthetic dataset.
 * Each day has a pattern of activity mimicking a real SOC.
 */
function generate30Days() {
  const logs: any[] = [];
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - 30);

  for (let day = 0; day < 30; day++) {
    const date = new Date(startDate);
    date.setDate(date.getDate() + day);

    for (const user of CTU_USERS) {
      const dayLogs = generateUserDay(user, date, day);
      logs.push(...dayLogs);
    }

    // Day 29 (last day of demo period): Inject the Nina exfiltration event
    if (day === 29) {
      logs.push(...generateNinaAttack(date));
    }
  }

  return logs;
}

function generateUserDay(
  user: (typeof CTU_USERS)[0],
  date: Date,
  dayIndex: number,
): any[] {
  const logs: any[] = [];
  const isWeekend = date.getDay() === 0 || date.getDay() === 6;
  const hour = new Date();

  // Each user has specific working hours
  let startHour: number, endHour: number, intensity: number;

  switch (user.role) {
    case 'director':
      startHour = 7;
      endHour = 16;
      intensity = 5; // Bill: light activity
      break;
    case 'vip':
      startHour = 9;
      endHour = 10;
      intensity = 3; // Palmer: very light
      break;
    default:
      startHour = user.principal === 'CTU\\jack.bauer' ? 5 : 8; // Jack starts early
      endHour = user.principal === 'CTU\\nina.myers' ? 20 : 18; // Nina stays late
      intensity = user.principal === 'CTU\\chloe.obrian' ? 30 : 15; // Chloe is power user
  }

  // Reduce intensity on weekends
  if (isWeekend && user.role !== 'analyst') return logs; // directors/VIPs don't work weekends
  if (isWeekend) intensity = Math.floor(intensity * 0.3); // analysts work less on weekends

  // Special: Nina works more weekends than others (foreshadowing)
  if (isWeekend && user.principal === 'CTU\\nina.myers') {
    intensity = Math.floor(intensity * 1.5);
  }

  const eventsPerDay = Math.max(
    3,
    intensity + Math.floor(Math.random() * intensity * 0.4),
  );

  for (let i = 0; i < eventsPerDay; i++) {
    const eventHour =
      startHour + Math.floor(Math.random() * (endHour - startHour));
    const eventMinute = Math.floor(Math.random() * 60);
    const eventSecond = Math.floor(Math.random() * 60);

    const eventDate = new Date(date);
    eventDate.setHours(eventHour, eventMinute, eventSecond);

    // Select host based on user
    const hostIndex = Math.floor(Math.random() * (user.role === 'vip' ? 2 : 5));
    const hostname = HOSTS[hostIndex];
    const sourceType =
      SOURCE_TYPES[Math.floor(Math.random() * SOURCE_TYPES.length)];
    const action = ACTIONS[Math.floor(Math.random() * ACTIONS.length)];
    const outcome = Math.random() > 0.2 ? 'success' : 'failure';

    let rawMessage: string;
    let eventId: number | undefined;
    let fileCount: number | undefined;

    // Generate realistic raw messages
    switch (sourceType) {
      case 'windows_security':
        eventId =
          action === 'login' ? (outcome === 'success' ? 4624 : 4625) : 4663;
        rawMessage =
          `Event ${eventId}: ${outcome === 'success' ? 'An account was successfully logged on' : 'An account failed to log on'}. ` +
          `Subject: Security ID: S-1-5-21-${Math.floor(Math.random() * 100000)}-${user.principal.replace('CTU\\', '')}. ` +
          `Logon Type: ${Math.floor(Math.random() * 5) + 2}. ` +
          `Source Network Address: 10.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`;
        break;
      case 'linux_auth':
        rawMessage = `${outcome === 'success' ? 'Accepted' : 'Failed'} password for ${user.principal.replace('CTU\\', '')} from 10.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1} port ${Math.floor(Math.random() * 60000) + 1024} ssh2`;
        break;
      case 'firewall':
        rawMessage = `PASS: ${user.principal.replace('CTU\\', '')} ${hostname} 10.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}:${Math.floor(Math.random() * 60000) + 1024} -> ${Math.floor(Math.random() * 200) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}:443 proto=tcp bytes=${Math.floor(Math.random() * 100000) + 500}`;
        break;
      case 'web_proxy':
        if (action === 'file_download') {
          fileCount = Math.floor(Math.random() * 5) + 1;
          rawMessage = `GET /secure/files/report_${Math.floor(Math.random() * 100)}.pdf - ${fileCount} files downloaded - user: ${user.principal.replace('CTU\\', '')}`;
        } else {
          rawMessage = `${user.principal.replace('CTU\\', '')} - ${hostname} - GET https://intranet.ctu.gov/ - 200 OK`;
        }
        break;
      default:
        rawMessage = `${outcome} | ${user.principal.replace('CTU\\', '')} | ${action}: ${sourceType} event on ${hostname}`;
    }

    const log = {
      collected_at: eventDate.toISOString(),
      source_type: sourceType,
      hostname,
      source_ip: `10.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`,
      destination_ip:
        action === 'network_connect'
          ? `192.168.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 254) + 1}`
          : undefined,
      user_principal: user.principal,
      event_taxonomy: TAXONOMIES[Math.floor(Math.random() * TAXONOMIES.length)],
      action:
        action === 'file_download' && fileCount ? 'file_download' : action,
      outcome,
      severity: outcome === 'failure' ? 5 : 0,
      raw_message: rawMessage,
      tags: [sourceType, outcome],
    };

    logs.push(log);
  }

  return logs;
}

/**
 * Generate the specific Nina Myers attack scenario (S7).
 * Day 29, 2:47 AM — Nina logs in, downloads 840 classified files.
 */
function generateNinaAttack(date: Date): any[] {
  const attackDate = new Date(date);
  attackDate.setHours(2, 47, 0);

  const logs: any[] = [];

  // Login at 2:47 AM (off-hours, unusual)
  logs.push({
    collected_at: attackDate.toISOString(),
    source_type: 'windows_security',
    hostname: 'CTU-DESK-03',
    source_ip: '10.0.0.47',
    user_principal: 'CTU\\nina.myers',
    event_taxonomy: 'T1078',
    action: 'login',
    outcome: 'success',
    severity: 0,
    raw_message:
      'Event 4624: An account was successfully logged on. ' +
      'Subject: Security ID: S-1-5-21-123456789-CTUnina.myers. ' +
      'Logon Type: 2. ' +
      'Source Network Address: 10.0.0.47',
    tags: ['windows_security', 'off_hours'],
  });

  // File server access at 2:48 AM
  logs.push({
    collected_at: new Date(attackDate.getTime() + 60000).toISOString(),
    source_type: 'web_proxy',
    hostname: 'CTU-DESK-03',
    source_ip: '10.0.0.47',
    destination_ip: '10.0.1.100',
    user_principal: 'CTU\\nina.myers',
    event_taxonomy: 'T1041',
    action: 'file_download',
    outcome: 'success',
    severity: 0,
    raw_message:
      'GET /classified/ctu/operations - 840 files downloaded - user: CTU\\nina.myers - ' +
      'source: 10.0.0.47 - target: classified-server-01',
    tags: ['web_proxy', 'exfiltration'],
  });

  // Bulk download confirmation at 2:49 AM
  logs.push({
    collected_at: new Date(attackDate.getTime() + 120000).toISOString(),
    source_type: 'web_proxy',
    hostname: 'CTU-DESK-03',
    source_ip: '10.0.0.47',
    destination_ip: '10.0.1.100',
    user_principal: 'CTU\\nina.myers',
    event_taxonomy: 'T1041',
    action: 'file_download',
    outcome: 'success',
    severity: 0,
    raw_message:
      'Event 4663: An attempt was made to access an object. Object: \\\\classified-server-01\\operations. ' +
      '840 files - access mask: ReadData - user: CTU\\nina.myers',
    tags: ['windows_security', 'exfiltration'],
  });

  // Multiple rapid downloads (simulate bulk exfiltration)
  for (let i = 0; i < 5; i++) {
    logs.push({
      collected_at: new Date(
        attackDate.getTime() + 180000 + i * 30000,
      ).toISOString(),
      source_type: 'web_proxy',
      hostname: 'CTU-DESK-03',
      source_ip: '10.0.0.47',
      destination_ip: `192.168.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 254) + 1}`,
      user_principal: 'CTU\\nina.myers',
      event_taxonomy: 'T1041',
      action: 'file_download',
      outcome: 'success',
      severity: 0,
      raw_message: `Bulk transfer - ${Math.floor(Math.random() * 100) + 50} files - CTU\\nina.myers - destination: remote`,
      tags: ['web_proxy', 'exfiltration'],
    });
  }

  return logs;
}

// ---- Main ----
async function main() {
  console.log('Generating 30 days of synthetic CTU logs...');
  const logs = generate30Days();
  console.log(`Generated ${logs.length} log events`);

  const apiUrl = process.env.API_URL;
  if (apiUrl) {
    // Bulk POST to the API in batches
    const BATCH_SIZE = 500;
    let imported = 0;

    for (let i = 0; i < logs.length; i += BATCH_SIZE) {
      const batch = logs.slice(i, i + BATCH_SIZE);
      try {
        const response = await fetch(`${apiUrl}/api/v1/logs`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-API-Key': process.env.API_KEY || 'ctu-collector-key',
          },
          body: JSON.stringify(batch),
        });
        const result = await response.json();
        imported += result.accepted ?? 0;
        console.log(
          `  Batch ${Math.floor(i / BATCH_SIZE) + 1}: ${result.accepted ?? 0} accepted`,
        );
      } catch (err: any) {
        console.error(
          `  Batch ${Math.floor(i / BATCH_SIZE) + 1} failed: ${err.message}`,
        );
      }
    }

    console.log(
      `\nDone. ${imported}/${logs.length} logs imported to ${apiUrl}`,
    );
  } else {
    // Output as NDJSON to stdout
    for (const log of logs) {
      console.log(JSON.stringify(log));
    }
    console.error(
      `\nTotal: ${logs.length} logs. Pipe to a file or set API_URL to POST to the backend.`,
    );
  }
}

main().catch(console.error);
