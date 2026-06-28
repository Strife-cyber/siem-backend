/**
 * Behavioral baseline stored in ueba_profiles.baseline_data (JSON column).
 * Built nightly from 30 days of historical logs.
 * Used by UebaScorerService to compute real-time risk scores.
 */
export interface UebaBaseline {
  /** Hours (0-23) the user is typically active */
  active_hours: number[];
  /** Average daily event volume */
  daily_volume_avg: number;
  /** Standard deviation of daily event volume */
  daily_volume_std: number;
  /** Known hostnames the user logs in from */
  known_hosts: string[];
  /** Known source IPs the user logs in from */
  known_ips: string[];
  /** Ratio of weekend activity (0.0 to 1.0) */
  weekend_ratio: number;
  /** Average file downloads per session */
  avg_file_downloads: number;
  /** Average login hour (decimal 0-23) */
  avg_login_hour: number;
  /** Standard deviation of login hours */
  login_hour_std: number;
  /** Average events per hour */
  avg_events_per_hour: number;
  /** Last 30 daily event counts for volume trend */
  daily_history: number[];
  /** When this baseline was computed */
  computed_at: string;
}

/**
 * Result of a single UEBA scoring evaluation.
 */
export interface UebaScoreResult {
  user_principal: string;
  event_score: number;
  risk_score_before: number;
  risk_score_after: number;
  breakdown: {
    off_hours: number;
    new_host: number;
    new_ip: number;
    weekend_activity: number;
    file_download_burst: number;
    login_deviation: number;
    demo_override: number;
  };
  triggered_soar: boolean;
}
