import React, { useEffect, useState } from 'react';
import { History as HistoryIcon, Search, Eye, FileText, Activity } from 'lucide-react';
import { investigationApi, reportApi } from '../api/client';
import { InvestigationSummaryItem } from '../types';
import { useNavigate } from 'react-router-dom';


export const HistoryPage: React.FC = () => {
  const [investigations, setInvestigations] = useState<InvestigationSummaryItem[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const data = await investigationApi.listInvestigations(0, 50);
        setInvestigations(data);
      } catch (err) {
        console.error('Failed to load investigation history:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchHistory();
  }, []);

  const handleGenerateOrViewReport = async (invId: string) => {
    try {
      const res = await reportApi.generateReport(invId);
      navigate(`/reports/${res.report_id}`);
    } catch (err) {
      console.error('Failed to generate report from history:', err);
    }
  };

  const filtered = investigations.filter((inv) =>
    inv.nl_query.toLowerCase().includes(searchTerm.toLowerCase()) ||
    inv.id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <HistoryIcon className="w-4 h-4 text-indigo-600" />
            Threat Investigation History
          </h2>
          <p className="text-xs text-slate-500">
            Audit trail of natural language investigations, generated queries, and retrieved evidence
          </p>
        </div>

        {/* Search bar */}
        <div className="relative max-w-xs w-full">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search queries or IDs..."
            className="w-full bg-white border border-slate-200 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-indigo-500 shadow-xs"
          />
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64 text-xs text-slate-500">
          <Activity className="w-4 h-4 animate-spin text-indigo-600 mr-2" />
          <span>Loading investigation archives...</span>
        </div>
      ) : (
        <div className="rounded-xl border border-slate-200 bg-white overflow-hidden shadow-xs">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-600 font-mono text-[11px] border-b border-slate-200">
              <tr>
                <th className="py-3 px-4">ID</th>
                <th className="py-3 px-4">Analyst Question</th>
                <th className="py-3 px-4">Hits</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono text-slate-700 text-[11px]">
              {filtered.length > 0 ? (
                filtered.map((inv) => (
                  <tr key={inv.id} className="hover:bg-indigo-50/30 transition-colors">
                    <td className="py-3 px-4 text-indigo-600 font-bold">{inv.id.slice(0, 8)}</td>
                    <td className="py-3 px-4 font-sans text-slate-800 font-medium">{inv.nl_query}</td>
                    <td className="py-3 px-4 text-slate-600">{inv.result_count}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 text-[10px] font-semibold">
                        {inv.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-500">
                      {inv.created_at ? inv.created_at.slice(0, 16).replace('T', ' ') : '-'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleGenerateOrViewReport(inv.id)}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 text-[11px] font-sans font-semibold transition-colors"
                      >
                        <FileText className="w-3.5 h-3.5" />
                        <span>Report</span>
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 italic">
                    {searchTerm ? 'No investigations match your search filter.' : 'No investigations saved yet.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );

};
