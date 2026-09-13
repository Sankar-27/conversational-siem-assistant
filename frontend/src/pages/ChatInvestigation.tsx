import React, { useState, useRef, useEffect } from 'react';
import { Send, Sparkles, RefreshCw, AlertCircle, Shield, Database, BookOpen, Layers, Activity } from 'lucide-react';
import { investigationApi } from '../api/client';
import { ChatMessage } from '../components/chat/ChatMessage';
import { InvestigationResponse } from '../types';
import { useAuth } from '../context/AuthContext';

interface MessageItem {
  role: 'user' | 'assistant';
  content: string;
  investigation?: InvestigationResponse;
}

const SAMPLE_QUERIES = [
  "Show me suspicious login activity.",
  "Are there signs of brute-force attacks?",
  "Investigate repeated failed logins from 185.220.101.45.",
  "What threats are associated with SQL injection or web scanning?",
  "Investigate this suspicious IP 203.0.113.99.",
  "Why was this event considered malicious?",
  "Detect distributed credential stuffing patterns.",
  "Investigate suspicious PowerShell commands or privilege escalation.",
];

export const ChatInvestigation: React.FC = () => {
  const { user } = useAuth();
  const isViewer = user?.role === 'viewer';

  const [messages, setMessages] = useState<MessageItem[]>([
    {
      role: 'assistant',
      content:
        "Welcome to Conversational SIEM. Ask security questions in natural language to investigate 10,000+ security logs with our 3-stage AI Agent workflow (Detection/Retrieval -> Investigation/Correlation -> Summary/Remediation) grounded across 20+ threat patterns.",
    },
  ]);
  const [inputQuery, setInputQuery] = useState('');
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isLoading]);

  const handleSend = async (queryText?: string) => {
    if (isViewer) return;
    const textToSend = (queryText || inputQuery).trim();
    if (!textToSend || isLoading) return;

    setError(null);
    setInputQuery('');

    const userMsg: MessageItem = { role: 'user', content: textToSend };
    setMessages((prev) => [...prev, userMsg]);
    setIsLoading(true);

    try {
      const response = await investigationApi.investigate(textToSend, conversationId || undefined);
      if (response.conversation_id) {
        setConversationId(response.conversation_id);
      }

      const assistantMsg: MessageItem = {
        role: 'assistant',
        content: response.conversational_response || response.explanation || `Retrieved ${response.retrieved_logs_count || response.result_count || 0} events from SIEM.`,
        investigation: response,
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      console.error('Investigation error:', err);
      setError(err.response?.data?.detail || 'Failed to execute investigation. Please check backend status.');
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: 'An error occurred during query execution. Please verify your query syntax or SIEM dataset status.',
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-4.5rem)] bg-slate-950 text-slate-100">
      {/* Top Banner with Quick Context */}
      <div className="px-6 py-3 border-b border-slate-800/80 bg-slate-900/50 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="font-semibold text-slate-200">Conversational SIEM Investigation Console</span>
          <span className="text-slate-500">•</span>
          <span className="text-slate-400">10,000+ Logs Indexed</span>
          <span className="text-slate-500">•</span>
          <span className="text-slate-400">20+ Threat Patterns</span>
        </div>
        <div className="flex items-center gap-2 text-slate-400 text-[11px] font-mono">
          <span>NLP + RAG + 3-Stage AI Agents</span>
        </div>
      </div>

      {/* Suggested Quick Prompts */}
      <div className="px-6 py-2.5 bg-slate-900/30 border-b border-slate-800/50 overflow-x-auto flex items-center gap-2 text-xs scrollbar-none">
        <span className="text-slate-500 shrink-0 font-medium text-[11px]">Quick Investigations:</span>
        {SAMPLE_QUERIES.map((q, idx) => (
          <button
            key={idx}
            onClick={() => handleSend(q)}
            disabled={isLoading || isViewer}
            className="shrink-0 px-2.5 py-1 rounded-full bg-slate-800/70 hover:bg-indigo-600/30 border border-slate-700/60 hover:border-indigo-500/50 text-slate-300 hover:text-indigo-200 transition-all text-[11px] disabled:opacity-40"
          >
            {q}
          </button>
        ))}
      </div>

      {/* Message Chat Feed */}
      <div className="flex-1 overflow-y-auto px-6 py-4 space-y-5">
        {messages.map((msg, i) => (
          <ChatMessage key={i} message={msg} />
        ))}

        {isLoading && (
          <div className="flex items-center gap-3 text-xs text-slate-400 bg-slate-900/60 border border-slate-800/80 p-3.5 rounded-xl max-w-md animate-pulse">
            <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin" />
            <span>Executing 3-stage agent investigation workflow across 10K+ logs...</span>
          </div>
        )}

        {error && (
          <div className="flex items-center gap-2 text-xs text-red-400 bg-red-950/40 border border-red-800/60 p-3 rounded-xl max-w-lg">
            <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Query Input Bar */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-900/60">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center gap-2 max-w-5xl mx-auto"
        >
          <div className="relative flex-1">
            <input
              type="text"
              value={inputQuery}
              onChange={(e) => setInputQuery(e.target.value)}
              placeholder={isViewer ? 'Read-only viewer account' : 'Ask a security question in natural language (e.g. "Investigate repeated failed logins from 185.220.101.45")...'}
              disabled={isLoading || isViewer}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all shadow-inner disabled:opacity-50"
            />
          </div>

          <button
            type="submit"
            disabled={!inputQuery.trim() || isLoading || isViewer}
            className="px-5 py-3 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white font-semibold text-sm shadow-md shadow-indigo-500/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center gap-2 shrink-0"
          >
            <span>Investigate</span>
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
};
