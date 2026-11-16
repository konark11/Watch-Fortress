import type { ChatMessage, RAGStatus } from "../../types";

export interface Conversation {
  id: string;
  title: string;
  status: "active" | "archived" | "deleted";
  created_at?: string;
  updated_at?: string;
  last_message_at?: string | null;
  expires_at: string;
}

export interface EvidenceSource {
  id?: string;
  source: string;
  title: string;
  relevance?: number;
  url?: string;
  chunk_id?: string | number;
}

export interface StoredMessage extends Omit<ChatMessage, "sources"> {
  id: string;
  sequence: number;
  citations?: EvidenceSource[];
  sources?: EvidenceSource[];
  provider?: string;
  model?: string | null;
  created_at?: string;
  expires_at?: string;
  generation_metadata?: {
    latency_ms?: number;
    degradation?: { reason?: string } | null;
    source_mode?: "grounded" | "general" | "external" | "insufficient_evidence";
  } | null;
  error?: boolean;
}

export interface Memory {
  id: string;
  memory_type: string;
  content: string;
  scope: "user" | "conversation";
  expires_at: string;
}

export interface StarterPrompt {
  id: string;
  category: "Scans & Assets" | "CVE & Hardening" | "Audit & Intel";
  title: string;
  prompt: string;
}

export type { RAGStatus };
