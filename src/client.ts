/**
 * Defensia API client — thin wrapper around the Sanctum-authenticated REST API.
 */

export interface DefensiaConfig {
  baseUrl: string;
  apiToken: string;
}

export class DefensiaClient {
  private baseUrl: string;
  private apiToken: string;

  constructor(config: DefensiaConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.apiToken = config.apiToken;
  }

  private async request<T>(path: string, options?: RequestInit): Promise<T> {
    const url = `${this.baseUrl}/api/v1${path}`;
    const res = await fetch(url, {
      ...options,
      headers: {
        'Authorization': `Bearer ${this.apiToken}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`Defensia API ${res.status}: ${res.statusText} — ${body}`);
    }

    return res.json() as Promise<T>;
  }

  // ── Dashboard ──────────────────────────────────────────────

  async getStats(): Promise<DashboardStats> {
    return this.request('/stats');
  }

  // ── Servers ────────────────────────────────────────────────

  async getServers(page = 1): Promise<PaginatedResponse<Server>> {
    return this.request(`/servers?page=${page}`);
  }

  async getServer(id: number): Promise<Server> {
    return this.request(`/servers/${id}`);
  }

  // ── Events ─────────────────────────────────────────────────

  async getEvents(params?: EventParams): Promise<PaginatedResponse<SecurityEvent>> {
    const qs = new URLSearchParams();
    if (params?.page) qs.set('page', String(params.page));
    if (params?.severity) qs.set('severity', params.severity);
    if (params?.type) qs.set('type', params.type);
    if (params?.server_id) qs.set('server_id', String(params.server_id));
    const query = qs.toString();
    return this.request(`/events${query ? '?' + query : ''}`);
  }

  // ── Bans ───────────────────────────────────────────────────

  async getBans(page = 1): Promise<PaginatedResponse<Ban>> {
    return this.request(`/bans?page=${page}`);
  }

  async createBan(ip: string, reason?: string): Promise<Ban> {
    return this.request('/bans', {
      method: 'POST',
      body: JSON.stringify({ ip_address: ip, reason }),
    });
  }

  async removeBan(id: number): Promise<{ message: string }> {
    return this.request(`/bans/${id}`, { method: 'DELETE' });
  }

  // ── Briefing (requires new endpoint) ───────────────────────

  async getBriefing(since = '12 hours'): Promise<Briefing> {
    return this.request(`/briefing?since=${encodeURIComponent(since)}`);
  }
}

// ── Type definitions ───────────────────────────────────────────

export interface DashboardStats {
  servers: {
    total: number;
    online: number;
    offline: number;
    warning: number;
  };
  events: {
    today: number;
    critical: number;
    total: number;
  };
  bans: {
    active: number;
    total: number;
  };
}

export interface Server {
  id: number;
  name: string;
  hostname: string;
  ip_address: string;
  status: 'online' | 'offline' | 'warning';
  os: string;
  os_version: string;
  version: string;
  last_seen_at: string;
  cpu_percent: number | null;
  memory_percent: number | null;
  disk_percent: number | null;
  monitor_mode: boolean;
  active_bans_count: number;
  waf_config: Record<string, unknown> | null;
  events?: SecurityEvent[];
  bans?: Ban[];
}

export interface SecurityEvent {
  id: number;
  agent_id: number;
  type: string;
  severity: 'info' | 'warning' | 'high' | 'critical';
  source_ip: string | null;
  country_code: string | null;
  source_port: number | null;
  target_port: number | null;
  protocol: string | null;
  details: Record<string, unknown> | null;
  occurred_at: string;
  agent?: { id: number; name: string };
}

export interface Ban {
  id: number;
  agent_id: number | null;
  ip_address: string;
  reason: string;
  ban_count: number;
  is_active: boolean;
  expires_at: string | null;
  created_at: string;
  agent?: { id: number; name: string };
}

export interface EventParams {
  page?: number;
  severity?: string;
  type?: string;
  server_id?: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  current_page: number;
  last_page: number;
  per_page: number;
  total: number;
}

export interface BriefingIncident {
  type: string;
  type_label: string;
  severity: string;
  server: string;
  server_id: number;
  started_at: string;
  ended_at: string;
  duration_minutes: number;
  event_count: number;
  source_ips: string[];
  source_countries: string[];
  auto_blocked: boolean;
  bans_applied: number;
  metrics_impact: {
    cpu_peak: number;
    cpu_baseline: number;
    memory_peak: number;
    resolved: boolean;
  } | null;
  narrative: string;
}

export interface Briefing {
  period: { from: string; to: string; label: string };
  status: 'all_clear' | 'incidents_handled' | 'attention_needed';
  summary: {
    total_events: number;
    critical_events: number;
    bans_created: number;
    bans_active: number;
    servers_online: number;
    servers_offline: number;
    servers_warning: number;
    servers_total: number;
  };
  incidents: BriefingIncident[];
  trends: {
    events_delta_percent: number;
    top_attack_type: string | null;
    top_countries: Record<string, number>;
  };
  resources: Array<{
    server: string;
    server_id: number;
    status: string;
    cpu_current: number | null;
    memory_current: number | null;
    disk_current: number | null;
    disk_warning: boolean;
  }>;
  recommendations: Array<{
    severity: string;
    title: string;
    description: string;
  }>;
  waf: {
    total: number;
    by_type: Array<{ type: string; label: string; count: number }>;
    top_type: string | null;
    top_type_label: string | null;
    scoring: {
      blocked: number;
      observed: number;
      throttled: number;
      top_ips: Array<{
        ip: string;
        max_score: number;
        action: string;
        category: string;
      }>;
    } | null;
  };
  security: {
    open_critical: number;
    open_high: number;
  };
}
