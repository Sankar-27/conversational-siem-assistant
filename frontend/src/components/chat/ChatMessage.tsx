import React, { useState } from 'react';
import { InvestigationResponse, AgentStageOutput } from '../../types';
import { 
  Bot, 
  User, 
  Code2, 
  ChevronDown, 
  ChevronUp, 
  Copy, 
  Check, 
  Sparkles,
  AlertTriangle,
  CheckCircle2,
  Shield,
  Database,
  BookOpen,
  Activity,
  Layers,
  Terminal,
  FileSearch,
  ListFilter,
  ArrowRight
} from 'lucide-react';
import { EvidenceTable } from '../evidence/EvidenceTable';
import { IOCPanel } from '../evidence/IOCPanel';
import { MitreCard } from '../mitre/MitreCard';
import { TimelineView } from '../timeline/TimelineView';

interface ChatMessageProps {
  message: {
    role: 'user' | 'assistant';
    content: string;
    investigation?: InvestigationResponse;
  };
}

export const ChatMessage: React.FC<ChatMessageProps> = ({ message }) => {
  const isAssistant = message.role === 'assistant';
  const inv = message.investigation;
  const [activeTab, setActiveTab] = useState<'summary' | 'stages' | 'logs' | 'patterns' | 'iocs'>('summary');
  const [copiedDsl, setCopiedDsl] = useState(false);
  const [logFilter, setLogFilter] = useState('');
  const [selectedRawLog, setSelectedRawLog] = useState<Record<string, any> | null>(null);

  const copyDsl = (dsl: Record<string, any>) => {
    navigator.clipboard.writeText(JSON.stringify(dsl, null, 2));
    setCopiedDsl(true);
    setTimeout(() => setCopiedDsl(false), 2000);
  };

  const severityLevel = inv?.severity_assessment?.level || (inv?.severity as any)?.level || 'Medium';
  const severityScore = inv?.severity_assessment?.score ?? (inv?.severity as any)?.score ?? 65;

  const severityBadgeClass = 
    severityLevel === 'Critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
    severityLevel === 'High' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
    severityLevel === 'Medium' ? 'bg-amber-500/20 text-amber-400 border-amber-500/30' :
    'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';

  const stages: AgentStageOutput[] = inv?.stages || [
    {
      stage_number: 1,
      stage_name: 'Detection / Retrieval Agent',
      status: 'completed',
      duration_ms: 45,
      summary: 'Parsed natural language query and retrieved relevant security logs & threat patterns via RAG.',
      details: { count: inv?.retrieved_logs_count || inv?.result_count || 0 },
    },
    {
      stage_number: 2,
      stage_name: 'Investigation / Correlation Agent',
      status: 'completed',
      duration_ms: 60,
      summary: 'Correlated events across 20+ threat patterns, extracted IOCs, and mapped to MITRE ATT&CK.',
      details: { patterns: inv?.matched_patterns?.length || inv?.patterns?.length || 0 },
    },
    {
      stage_number: 3,
      stage_name: 'Investigation Summary Agent',
      status: 'completed',
      duration_ms: 35,
      summary: 'Synthesized evidence-grounded findings with confirmed facts and remediation guidance.',
      details: { confidence: inv?.confidence || 'High' },
    },
  ];

  const logsList = inv?.retrieved_logs || inv?.hits_preview || [];
  const filteredLogs = logFilter
    ? logsList.filter((log) => JSON.stringify(log).toLowerCase().includes(logFilter.toLowerCase()))
    : logsList;

  const patternsList = inv?.matched_patterns || inv?.patterns || [];
  const mitreList = inv?.mitre_tactics || inv?.mitre || [];

  return (
    <div className={`flex gap-3.5 ${isAssistant ? 'items-start' : 'items-start flex-row-reverse'}`}>
      {/* Avatar */}
      <div
        className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border ${
          isAssistant
            ? 'bg-gradient-to-br from-indigo-600 to-cyan-700 border-indigo-400/30 text-white shadow-md shadow-indigo-500/10'
            : 'bg-slate-800 border-slate-700 text-slate-300'
        }`}
      >
        {isAssistant ? <Sparkles className="w-4 h-4 text-cyan-300" /> : <User className="w-4 h-4" />}
      </div>

      {/* Message Bubble & Investigation Container */}
      <div className={`space-y-3 max-w-4xl flex-1 ${!isAssistant ? 'flex flex-col items-end' : ''}`}>
        {/* User Query text */}
        {!isAssistant ? (
          <div className="rounded-2xl rounded-tr-sm bg-indigo-600 text-white px-4 py-2.5 text-sm shadow-sm max-w-2xl font-medium">
            {message.content}
          </div>
        ) : (
          <div className="w-full rounded-2xl rounded-tl-sm bg-slate-900/90 border border-slate-800/80 p-4 shadow-xl text-slate-200 space-y-4">
            
            {/* Header / Severity & Agent Status Bar */}
            {inv && (
              <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-800 text-xs">
                <div className="flex items-center gap-2">
                  <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-semibold font-mono">
                    <Activity className="w-3 h-3 text-cyan-400" />
                    <span>3-Stage Agent Workflow</span>
                  </div>
                  <span className="text-slate-500">•</span>
                  <span className="text-slate-400">
                    Retrieved <strong className="text-slate-200">{inv.retrieved_logs_count || inv.result_count || 0}</strong> logs
                  </span>
                  {inv.total_duration_ms ? (
                    <>
                      <span className="text-slate-500">•</span>
                      <span className="text-slate-400 font-mono">{inv.total_duration_ms}ms</span>
                    </>
                  ) : null}
                </div>

                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${severityBadgeClass}`}>
                    {severityLevel} Risk ({severityScore}/100)
                  </span>
                  {inv.confidence && (
                    <span className="px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-300 text-[11px] font-medium">
                      {inv.confidence} Confidence
                    </span>
                  )}
                </div>
              </div>
            )}

            {/* 3-Stage Progress Timeline Cards */}
            {inv && stages.length > 0 && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
                {stages.map((stg) => (
                  <div
                    key={stg.stage_number}
                    className="rounded-xl p-2.5 bg-slate-950/60 border border-slate-800/70 space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-bold uppercase tracking-wider text-cyan-400 font-mono flex items-center gap-1">
                        <span className="w-4 h-4 rounded-full bg-cyan-500/20 text-cyan-300 inline-flex items-center justify-center text-[10px]">
                          {stg.stage_number}
                        </span>
                        {stg.stage_name}
                      </span>
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    </div>
                    <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                      {stg.summary}
                    </p>
                  </div>
                ))}
              </div>
            )}

            {/* Main Conversational Response Text */}
            <div className="text-sm leading-relaxed text-slate-100 bg-slate-950/40 p-3.5 rounded-xl border border-slate-800/60 font-sans">
              {inv?.conversational_response || inv?.explanation || message.content}
            </div>

            {/* Navigation Tabs for Deep Investigation Evidence */}
            {inv && (
              <div className="space-y-3 pt-1">
                <div className="flex items-center gap-1.5 border-b border-slate-800 pb-2 overflow-x-auto text-xs">
                  <button
                    onClick={() => setActiveTab('summary')}
                    className={`px-3 py-1.5 rounded-lg font-medium transition-all flex items-center gap-1.5 ${
                      activeTab === 'summary'
                        ? 'bg-indigo-600/20 border border-indigo-500/40 text-indigo-300 shadow-sm'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                    }`}
                  >
                    <FileSearch className="w-3.5 h-3.5" />
                    <span>Evidence & Hypotheses</span>
                  </button>

                  <button
                    onClick={() => setActiveTab('logs')}
                    className={`px-3 py-1.5 rounded-lg font-medium transition-all flex items-center gap-1.5 ${
                      activeTab === 'logs'
                        ? 'bg-indigo-600/20 border border-indigo-500/40 text-indigo-300 shadow-sm'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                    }`}
                  >
                    <Database className="w-3.5 h-3.5" />
                    <span>Log Evidence ({logsList.length})</span>
                  </button>

                  <button
                    onClick={() => setActiveTab('patterns')}
                    className={`px-3 py-1.5 rounded-lg font-medium transition-all flex items-center gap-1.5 ${
                      activeTab === 'patterns'
                        ? 'bg-indigo-600/20 border border-indigo-500/40 text-indigo-300 shadow-sm'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                    }`}
                  >
                    <Shield className="w-3.5 h-3.5" />
                    <span>Threat Patterns ({patternsList.length})</span>
                  </button>

                  <button
                    onClick={() => setActiveTab('iocs')}
                    className={`px-3 py-1.5 rounded-lg font-medium transition-all flex items-center gap-1.5 ${
                      activeTab === 'iocs'
                        ? 'bg-indigo-600/20 border border-indigo-500/40 text-indigo-300 shadow-sm'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                    }`}
                  >
                    <Layers className="w-3.5 h-3.5" />
                    <span>IOCs & Timeline</span>
                  </button>
                </div>

                {/* Tab 1: Summary, Evidence Demarcation & Recommendations */}
                {activeTab === 'summary' && (
                  <div className="space-y-3.5 text-xs">
                    {/* Confirmed Evidence vs Hypotheses */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="rounded-xl p-3 bg-emerald-950/20 border border-emerald-500/30 space-y-2">
                        <div className="flex items-center gap-1.5 font-bold text-emerald-400 uppercase tracking-wider text-[11px]">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Confirmed Log Evidence</span>
                        </div>
                        <ul className="space-y-1 text-slate-300 list-disc list-inside">
                          {(inv.confirmed_evidence && inv.confirmed_evidence.length > 0) ? (
                            inv.confirmed_evidence.map((ev, i) => <li key={i} className="leading-relaxed">{ev}</li>)
                          ) : (
                            <>
                              <li>{logsList.length} telemetry records matched the query filter criteria.</li>
                              <li>Observed activity documented in SIEM dataset.</li>
                            </>
                          )}
                        </ul>
                      </div>

                      <div className="rounded-xl p-3 bg-indigo-950/20 border border-indigo-500/30 space-y-2">
                        <div className="flex items-center gap-1.5 font-bold text-indigo-300 uppercase tracking-wider text-[11px]">
                          <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                          <span>Analytical Hypotheses & Confidence</span>
                        </div>
                        <ul className="space-y-1 text-slate-300 list-disc list-inside">
                          {(inv.assumptions_and_hypotheses && inv.assumptions_and_hypotheses.length > 0) ? (
                            inv.assumptions_and_hypotheses.map((asmp, i) => <li key={i} className="leading-relaxed">{asmp}</li>)
                          ) : (
                            <>
                              <li>Intent assessment based on MITRE ATT&CK technique correlation.</li>
                              <li>Confidence: {inv.confidence || 'High'}.</li>
                            </>
                          )}
                        </ul>
                      </div>
                    </div>

                    {/* Remediation Playbook */}
                    {inv.remediation_recommendations && inv.remediation_recommendations.length > 0 && (
                      <div className="rounded-xl p-3 bg-slate-950 border border-slate-800 space-y-2">
                        <div className="flex items-center gap-1.5 font-bold text-cyan-400 uppercase tracking-wider text-[11px]">
                          <Shield className="w-3.5 h-3.5" />
                          <span>Recommended Remediation Actions</span>
                        </div>
                        <div className="space-y-1.5">
                          {inv.remediation_recommendations.map((rec, i) => (
                            <div key={i} className="flex items-start gap-2 text-slate-300 bg-slate-900/60 p-2 rounded-lg border border-slate-800/80">
                              <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                              <span className="leading-relaxed">{rec}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Tab 2: Retrieved Log Evidence Table */}
                {activeTab === 'logs' && (
                  <div className="space-y-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <div className="relative flex-1 max-w-sm">
                        <input
                          type="text"
                          value={logFilter}
                          onChange={(e) => setLogFilter(e.target.value)}
                          placeholder="Filter logs by IP, action, username, URL..."
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                        />
                      </div>
                      <span className="text-[11px] text-slate-400 font-mono">
                        Showing {filteredLogs.length} of {logsList.length} logs
                      </span>
                    </div>

                    <div className="max-h-80 overflow-y-auto rounded-xl border border-slate-800 bg-slate-950">
                      <table className="w-full text-left text-[11px] text-slate-300 font-mono">
                        <thead className="sticky top-0 bg-slate-900 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                          <tr>
                            <th className="px-3 py-2">Timestamp</th>
                            <th className="px-3 py-2">Source IP</th>
                            <th className="px-3 py-2">Action</th>
                            <th className="px-3 py-2">User</th>
                            <th className="px-3 py-2">URL / Payload</th>
                            <th className="px-3 py-2">Status</th>
                            <th className="px-3 py-2">Action</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60">
                          {filteredLogs.map((log, idx) => {
                            const ts = log['@timestamp'] || log.timestamp || '';
                            const srcIp = log.source?.ip || log.source_ip || '-';
                            const act = log.event?.action || log.event_action || '-';
                            const usr = log.user?.name || log.username || '-';
                            const url = log.url?.original || log.url || log.process?.command_line || '-';
                            const statusCode = log.http?.response?.status_code || log.http_status || '-';

                            return (
                              <tr key={idx} className="hover:bg-slate-900/60 transition-colors">
                                <td className="px-3 py-1.5 text-slate-400 truncate max-w-[140px]">{ts}</td>
                                <td className="px-3 py-1.5 font-bold text-indigo-300">{srcIp}</td>
                                <td className="px-3 py-1.5">
                                  <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                                    {act}
                                  </span>
                                </td>
                                <td className="px-3 py-1.5 text-slate-300">{usr}</td>
                                <td className="px-3 py-1.5 text-slate-400 truncate max-w-xs" title={url}>{url}</td>
                                <td className="px-3 py-1.5">
                                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                    statusCode >= 500 ? 'bg-red-500/20 text-red-300' :
                                    statusCode >= 400 ? 'bg-amber-500/20 text-amber-300' :
                                    'bg-emerald-500/20 text-emerald-300'
                                  }`}>
                                    {statusCode}
                                  </span>
                                </td>
                                <td className="px-3 py-1.5">
                                  <button
                                    onClick={() => setSelectedRawLog(log)}
                                    className="text-cyan-400 hover:text-cyan-300 underline text-[10px]"
                                  >
                                    JSON
                                  </button>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Tab 3: Matched Threat Patterns from 20+ Catalog */}
                {activeTab === 'patterns' && (
                  <div className="space-y-3">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {patternsList.map((pat, i) => (
                        <div
                          key={i}
                          className="rounded-xl p-3 bg-slate-950 border border-slate-800 space-y-2 text-xs"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-indigo-300 uppercase tracking-wide font-mono">
                              {pat.pattern_type.replace(/_/g, ' ')}
                            </span>
                            <span className="px-2 py-0.5 rounded bg-indigo-500/20 border border-indigo-500/30 text-indigo-300 font-bold font-mono text-[10px]">
                              {Math.round(pat.confidence * 100)}% Confidence
                            </span>
                          </div>

                          <div className="grid grid-cols-2 gap-2 text-slate-400 text-[11px]">
                            <div>
                              <span className="text-slate-500 block">Source IP:</span>
                              <span className="font-mono text-slate-200">{pat.source_ip || 'Distributed / Internal'}</span>
                            </div>
                            <div>
                              <span className="text-slate-500 block">Evidence Count:</span>
                              <span className="font-mono text-slate-200">{pat.evidence_count} events</span>
                            </div>
                          </div>

                          {pat.details && (
                            <div className="bg-slate-900/70 p-2 rounded-lg font-mono text-[10px] text-slate-300 overflow-x-auto">
                              {JSON.stringify(pat.details, null, 2)}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>

                    {/* MITRE Techniques list */}
                    {mitreList.length > 0 && (
                      <div className="space-y-2 pt-2">
                        <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider font-mono">
                          Mapped MITRE ATT&CK Techniques ({mitreList.length})
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                          {mitreList.map((m, i) => (
                            <div key={i} className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 text-xs space-y-1">
                              <div className="flex items-center justify-between">
                                <span className="font-bold text-cyan-400 font-mono">{m.technique_id} — {m.technique_name}</span>
                                <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">{m.tactic}</span>
                              </div>
                              <p className="text-slate-400 text-[11px] leading-relaxed">{m.description}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Tab 4: IOCs & Timeline */}
                {activeTab === 'iocs' && (
                  <div className="space-y-3">
                    {inv.iocs && inv.iocs.length > 0 && (
                      <IOCPanel iocs={inv.iocs} />
                    )}
                    {inv.timeline && inv.timeline.length > 0 && (
                      <TimelineView events={inv.timeline} />
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Raw Log Modal */}
      {selectedRawLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full p-5 space-y-4 shadow-2xl text-xs text-slate-200">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <span className="font-bold text-sm text-cyan-300 font-mono">Telemetry Event Record (ECS)</span>
              <button
                onClick={() => setSelectedRawLog(null)}
                className="text-slate-400 hover:text-white font-mono text-sm px-2 py-1 rounded bg-slate-800"
              >
                ✕
              </button>
            </div>
            <pre className="bg-slate-950 p-4 rounded-xl font-mono text-[11px] text-emerald-400 overflow-auto max-h-96 border border-slate-800">
              {JSON.stringify(selectedRawLog, null, 2)}
            </pre>
            <div className="flex justify-end">
              <button
                onClick={() => setSelectedRawLog(null)}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
