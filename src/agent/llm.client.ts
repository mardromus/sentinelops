/**
 * OpenAI-compatible chat-completions client with tool calling.
 * Works with Groq, OpenAI, Together, Ollama (/v1) and any compatible gateway.
 */
export interface ToolCall {
  id: string;
  name: string;
  arguments: string; // raw JSON text from the model
}

export type ChatMessage =
  | { role: 'system' | 'user'; content: string }
  | { role: 'assistant'; content: string | null; tool_calls?: { id: string; type: 'function'; function: { name: string; arguments: string } }[] }
  | { role: 'tool'; tool_call_id: string; content: string };

export interface ToolSpec {
  name: string;
  description: string;
  parameters: Record<string, unknown>; // JSON schema
}

export interface LlmResponse {
  content: string | null;
  toolCalls: ToolCall[];
  usage?: { prompt: number; completion: number };
}

export interface LlmClient {
  readonly model: string;
  chat(messages: ChatMessage[], tools: ToolSpec[]): Promise<LlmResponse>;
}

type FetchFn = typeof fetch;

export class OpenAiCompatibleClient implements LlmClient {
  constructor(
    private readonly baseUrl: string,
    private readonly apiKey: string,
    readonly model: string,
    private readonly http: FetchFn = fetch,
    private readonly opts: { timeoutMs?: number; retries?: number; temperature?: number } = {},
  ) {}

  async chat(messages: ChatMessage[], tools: ToolSpec[]): Promise<LlmResponse> {
    const body = {
      model: this.model,
      temperature: this.opts.temperature ?? 0.1,
      messages,
      tools: tools.map((t) => ({ type: 'function', function: t })),
      tool_choice: tools.length ? 'auto' : undefined,
    };
    const retries = this.opts.retries ?? 2;
    let lastErr: Error | undefined;
    for (let attempt = 0; attempt <= retries; attempt++) {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), this.opts.timeoutMs ?? 60_000);
      try {
        const res = await this.http(`${this.baseUrl}/chat/completions`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: `Bearer ${this.apiKey}` },
          body: JSON.stringify(body),
          signal: ctl.signal,
        });
        if (res.status === 429 || res.status >= 500) {
          lastErr = new Error(`LLM HTTP ${res.status}`);
          await new Promise((r) => setTimeout(r, 500 * 2 ** attempt));
          continue;
        }
        if (!res.ok) throw new Error(`LLM HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
        const data: any = await res.json();
        const msg = data.choices?.[0]?.message || {};
        return {
          content: msg.content ?? null,
          toolCalls: (msg.tool_calls || []).map((c: any, i: number) => ({ id: c.id || `call_${i}`, name: c.function?.name, arguments: c.function?.arguments || '{}' })),
          usage: data.usage ? { prompt: data.usage.prompt_tokens, completion: data.usage.completion_tokens } : undefined,
        };
      } catch (e) {
        lastErr = e as Error;
        if ((e as Error).name !== 'AbortError' && !/HTTP (429|5\d\d)/.test((e as Error).message)) throw e;
      } finally {
        clearTimeout(timer);
      }
    }
    throw lastErr || new Error('LLM request failed');
  }
}

/** Parse tool arguments defensively: models sometimes wrap JSON in prose or code fences. */
export function parseArgs(raw: string): Record<string, unknown> {
  try {
    const v = JSON.parse(raw || '{}');
    return v && typeof v === 'object' ? v : {};
  } catch {
    const m = /\{[\s\S]*\}/.exec(raw || '');
    if (m) {
      try {
        return JSON.parse(m[0]);
      } catch {
        /* fall through */
      }
    }
    return {};
  }
}
