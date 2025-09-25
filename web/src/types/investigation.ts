export enum InvestigationStatus {
  CREATED = 'created',
  PLANNING = 'planning',
  ACTIVE = 'active',
  PAUSED = 'paused',
  COMPLETED = 'completed',
  FAILED = 'failed',
  ARCHIVED = 'archived'
}

export enum TaskStatus {
  PENDING = 'pending',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  SKIPPED = 'skipped',
  RETRY = 'retry'
}

export enum Priority {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export enum InvestigationType {
  DOMAIN = 'domain',
  IP = 'ip',
  EMAIL = 'email',
  PERSON = 'person',
  COMPANY = 'company',
  PHONE = 'phone',
  CRYPTO = 'crypto',
  MIXED = 'mixed'
}

export interface InvestigationTask {
  id: string;
  name: string;
  task_type: string;
  targets: string[];
  parameters: Record<string, any>;
  status: TaskStatus;
  priority: Priority;
  dependencies: string[];
  estimated_duration: number;
  actual_duration?: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  result?: Record<string, any>;
  error?: string;
  retry_count: number;
  max_retries: number;
  progress: number;
  metadata: Record<string, any>;
}

export interface Investigation {
  id: string;
  name: string;
  description: string;
  investigation_type: string;
  status: InvestigationStatus;
  priority: Priority;
  targets: string[];
  tags: string[];
  analyst: string;
  organization: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  deadline?: string;
  estimated_duration: number;
  tasks: Record<string, InvestigationTask>;
  dependencies: Record<string, string[]>;
  results: Record<string, any>;
  ai_analysis?: Record<string, any>;
  configuration: Record<string, any>;
  metadata: Record<string, any>;
}

export interface InvestigationProgress {
  investigation_id: string;
  status: string;
  overall_progress: number;
  total_tasks: number;
  completed_tasks: number;
  failed_tasks: number;
  running_tasks: number;
  estimated_completion?: string;
  task_progress: Record<string, {
    name: string;
    status: string;
    progress: number;
  }>;
}

export interface CreateInvestigationRequest {
  name: string;
  description: string;
  investigation_type: InvestigationType;
  targets: string[];
  analyst?: string;
  organization?: string;
  priority?: Priority;
  deadline?: string;
  tags?: string[];
  configuration?: Record<string, any>;
}

export interface ListInvestigationsRequest {
  status?: InvestigationStatus;
  analyst?: string;
  investigation_type?: string;
  limit?: number;
}

export interface AIAnalysisResult {
  analysis_type: string;
  summary: string;
  findings: Array<Record<string, any>>;
  confidence_score: number;
  recommendations: string[];
  threat_level: string;
  metadata: Record<string, any>;
  generated_at: string;
}

export interface WebSocketMessage {
  type: string;
  investigation_id?: string;
  investigation_name?: string;
  task_id?: string;
  task_name?: string;
  updates?: Record<string, any>;
  data?: any;
  timestamp: string;
}