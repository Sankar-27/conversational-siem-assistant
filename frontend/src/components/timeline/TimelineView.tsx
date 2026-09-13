import React from 'react';
import { TimelineEvent, TimelineSummary } from '../../types';
import { Clock, CheckCircle2, AlertTriangle, Flame, Shield } from 'lucide-react';

interface TimelineViewProps {
  events: TimelineEvent[];
  summary?: TimelineSummary;
}

export const TimelineView: React.FC<TimelineViewProps> = ({ events, summary }) => {
  if (!events || events.length === 0) {
    return (
      <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-500 italic text-center">
        No attack sequence timeline reconstructed.
      </div>
    );
  }

  const getPhaseColor = (phase: string) => {
    switch (phase.toLowerCase()) {
      case 'reconnaissance':
        return 'border-sky-200 bg-sky-50 text-sky-700 font-semibold';
      case 'initial_access':
      case 'credential_access':
        return 'border-amber-200 bg-amber-50 text-amber-700 font-semibold';
      case 'execution':
      case 'persistence':
        return 'border-purple-200 bg-purple-50 text-purple-700 font-semibold';
      case 'impact':
      case 'exfiltration':
        return 'border-rose-200 bg-rose-50 text-rose-700 font-semibold';
      default:
        return 'border-slate-200 bg-slate-100 text-slate-700';
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center gap-1.5">
          <Clock className="w-3.5 h-3.5 text-amber-600" />
          Attack Sequence Timeline ({events.length} milestones)
        </h4>

        {summary?.phase_sequence && summary.phase_sequence.length > 0 && (
          <div className="flex items-center gap-1.5 text-[10px] text-slate-500">
            <span>Phases:</span>
            {summary.phase_sequence.map((p, i) => (
              <span key={i} className="px-1.5 py-0.5 rounded bg-slate-100 font-mono text-slate-700 border border-slate-200">
                {p.replace(/_/g, ' ')}
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="relative pl-6 space-y-4 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200">
        {events.slice(0, 15).map((evt, idx) => {
          const isHigh = evt.severity >= 8;
          return (
            <div key={idx} className="relative group">
              {/* Timeline marker node */}
              <div
                className={`absolute -left-[22px] top-1 w-3 h-3 rounded-full border-2 ${
                  isHigh ? 'bg-rose-500 border-rose-200 animate-pulse' : 'bg-white border-indigo-600'
                }`}
              />

              <div className="p-3 rounded-lg bg-white border border-slate-200 group-hover:border-slate-300 transition-all space-y-1 shadow-xs">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono border uppercase tracking-wider ${getPhaseColor(evt.phase)}`}>
                      {evt.phase.replace(/_/g, ' ')}
                    </span>
                    <span className="text-xs font-bold text-slate-900">
                      {evt.description}
                    </span>
                  </div>
                  <span className="font-mono text-[11px] text-slate-400">
                    {evt.timestamp ? evt.timestamp.replace('T', ' ').slice(0, 19) : ''}
                  </span>
                </div>

                <div className="flex items-center gap-4 text-[11px] text-slate-500 pt-1">
                  {evt.source_ip && (
                    <span>
                      IP: <strong className="text-indigo-600 font-mono font-semibold">{evt.source_ip}</strong>
                    </span>
                  )}
                  {evt.username && (
                    <span>
                      User: <strong className="text-amber-700 font-semibold">{evt.username}</strong>
                    </span>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

