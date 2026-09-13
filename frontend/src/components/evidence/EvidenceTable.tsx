import React, { useState } from 'react';
import { Terminal, Eye, AlertCircle } from 'lucide-react';

interface EvidenceTableProps {
  hits: Array<Record<string, any>>;
  totalCount: number;
}

export const EvidenceTable: React.FC<EvidenceTableProps> = ({ hits, totalCount }) => {
  const [selectedLog, setSelectedLog] = useState<Record<string, any> | null>(null);

  if (!hits || hits.length === 0) {
    return (
      <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-500 italic text-center">
        No log hits retrieved.
      </div>
    );
  }

  const getSeverityBadge = (severity?: number) => {
    const sev = severity || 3;
    if (sev >= 8) {
      return <span className="px-1.5 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 text-[10px] font-mono font-semibold">High ({sev})</span>;
    }
    if (sev >= 5) {
      return <span className="px-1.5 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200 text-[10px] font-mono font-semibold">Med ({sev})</span>;
    }
    return <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200 text-[10px] font-mono">Low ({sev})</span>;
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center gap-1.5">
          <Terminal className="w-3.5 h-3.5 text-indigo-600" />
          Retrieved Security Evidence ({hits.length} of {totalCount} events)
        </h4>
      </div>

      <div className="rounded-lg border border-slate-200 overflow-hidden bg-white shadow-xs">
        <div className="max-h-60 overflow-y-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-600 font-mono text-[11px] sticky top-0 border-b border-slate-200">
              <tr>
                <th className="py-2.5 px-3">Timestamp (UTC)</th>
                <th className="py-2.5 px-3">Source IP</th>
                <th className="py-2.5 px-3">User</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono text-slate-700 text-[11px]">
              {hits.map((hit, idx) => {
                const ts = hit['@timestamp'] || '';
                const srcIp = hit.source?.ip || 'N/A';
                const user = hit.user?.name || '-';
                const action = hit.event?.action || 'unknown';
                const status = hit.http?.response?.status_code || '-';
                const sev = hit.event?.severity;

                return (
                  <tr key={idx} className="hover:bg-indigo-50/40 transition-colors">
                    <td className="py-2 px-3 text-slate-500">{ts ? ts.replace('T', ' ').slice(0, 19) : '-'}</td>
                    <td className="py-2 px-3 text-indigo-600 font-semibold">{srcIp}</td>
                    <td className="py-2 px-3 text-amber-700 font-semibold">{user}</td>
                    <td className="py-2 px-3 text-slate-800">{action.replace(/_/g, ' ')}</td>
                    <td className="py-2 px-3">
                      {status !== '-' ? (
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                          Number(status) >= 400 ? 'bg-rose-50 text-rose-700 border border-rose-200' : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                        }`}>
                          {status}
                        </span>
                      ) : '-'}
                    </td>
                    <td className="py-2 px-3">{getSeverityBadge(sev)}</td>
                    <td className="py-2 px-3 text-right">
                      <button
                        onClick={() => setSelectedLog(hit)}
                        className="p-1 rounded hover:bg-slate-100 text-slate-400 hover:text-slate-700 transition-colors"
                        title="View Full JSON Log"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Log detail modal */}
      {selectedLog && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-white border border-slate-200 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-indigo-600" />
                Raw Normalized Log Event
              </h3>
              <button
                onClick={() => setSelectedLog(null)}
                className="text-xs text-slate-500 hover:text-slate-800 px-2.5 py-1 rounded bg-slate-100 border border-slate-200"
              >
                Close
              </button>
            </div>
            <pre className="p-4 rounded-lg bg-slate-950 text-emerald-400 font-mono text-xs overflow-x-auto max-h-96 border border-slate-800">
              {JSON.stringify(selectedLog, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );

};
