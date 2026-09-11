/* Chat history, stored as whole conversations rather than loose messages.
 *
 * The sidebar lists one row per thread — titled by how the thread opened — the way
 * the Claude apps list them. An earlier version pushed every question into the list
 * as its own entry, which turned a four-question conversation into four rows that
 * all reopened the same place.
 *
 * Everything here is localStorage only: chat never leaves the appliance. */
import { safeParse } from './api';

export type Turn = { role: 'me' | 'them'; text: string };
export type Conversation = { id: string; title: string; turns: Turn[]; updated: number };

const KEY = 'lighthouse-chats';
const TITLE_LIMIT = 48;
/* Superseded by KEY: it held individual questions, so carrying it forward would
 * reintroduce exactly the per-message rows this module replaces. */
const LEGACY_KEY = 'lighthouse-recent-chats';

const isTurn = (value: unknown): boolean => {
  const turn = value as Turn;
  return !!turn && typeof turn === 'object' && (turn.role === 'me' || turn.role === 'them') && typeof turn.text === 'string';
};

const isConversation = (value: unknown): boolean => {
  const chat = value as Conversation;
  return !!chat && typeof chat === 'object' && typeof chat.id === 'string' && typeof chat.title === 'string'
    && Array.isArray(chat.turns) && chat.turns.every(isTurn);
};

export function loadConversations(): Conversation[] {
  try { localStorage.removeItem(LEGACY_KEY); } catch { /* a blocked store is not a failure */ }
  const stored = safeParse<Conversation[]>(KEY, [], value => Array.isArray(value) && value.every(isConversation));
  return [...stored].sort((a, b) => (b.updated || 0) - (a.updated || 0));
}

export function saveConversations(chats: Conversation[]): void {
  try { localStorage.setItem(KEY, JSON.stringify(chats)); } catch { /* a private or full store must not break chat */ }
}

export const titleFor = (question: string) => {
  const trimmed = question.trim().replace(/\s+/g, ' ');
  return trimmed.length > TITLE_LIMIT ? `${trimmed.slice(0, TITLE_LIMIT - 1)}…` : trimmed;
};

/* crypto.randomUUID is absent over plain HTTP on some browsers, and this dashboard
 * is served over HTTP on the LAN until TLS is configured. */
export const newId = () => (globalThis.crypto?.randomUUID?.() ?? `c${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`);
