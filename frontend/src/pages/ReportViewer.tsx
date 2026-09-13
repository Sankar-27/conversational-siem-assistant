import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { 
  FileText, 
  Download, 
  ArrowLeft, 
  ShieldAlert, 
  Target, 
  Clock, 
  Key, 
  Activity, 
  Terminal, 
  CheckCircle2 
} from 'lucide-react';
import { reportApi } from '../api/client';
import { IncidentReport } from '../types';
import { IOCPanel } from '../components/evidence/IOCPanel';
import { MitreCard } from '../components/mitre/MitreCard';
import { TimelineView } from '../components/timeline/TimelineView';
import { EvidenceTable } from '../components/evidence/EvidenceTable';


export const ReportViewer: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [report, setReport] = useState<IncidentReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    if (!id) return;
    const fetchReport = async () => {
      try {
        const data = await reportApi.getReport(id);
        setReport(data);
      } catch (err) {
        console.error('Failed to load report:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchReport();
  }, [id]);

  const handleDownloadPdf = async () => {
    if (!id) return;
    setDownloading(true);
    try {
      const blob = await reportApi.downloadPdf(id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `incident_report_${id.slice(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error('Failed to download PDF:', err);
    } finally {
      setDownloading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-slate-400 text-xs flex items-center gap-2">
          <Activity className="w-4 h-4 animate-spin text-indigo-500" />
          <span>Rendering structured incident report...</span>
        </div>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="max-w-4xl mx-auto p-12 text-center space-y-4">
        <ShieldAlert className="w-12 h-12 text-rose-400 mx-auto" />
        <h3 className="text-lg font-bold text-white">Incident Report Not Found</h3>
        <p className="text-xs text-slate-400">The requested report ID could not be loaded from database.</p>
        <Link to="/chat" className="inline-flex items-center gap-2 text-xs text-indigo-400 hover:text-indigo-300">
          <ArrowLeft className="w-4 h-4" />
          Back to Copilot
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-12">
      {/* Top action toolbar */}
      <div className="flex items-center justify-between">
        <Link
          to="/chat"
          className="flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Investigation</span>
        </Link>

        <button
          onClick={handleDownloadPdf}
          disabled={downloading}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs shadow-md shadow-indigo-600/20 transition-all disabled:opacity-50"
        >
          <Download className="w-3.5 h-3.5" />
          <span>{downloading ? 'Compiling PDF...' : 'Download PDF Report'}</span>
        </button>
      </div>

      {/* Formal Report Paper Frame */}
      <div className="bg-white border border-slate-200 rounded-2xl p-8 space-y-8 shadow-md">
        {/* Report Header */}
        <div className="border-b border-slate-200 pb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-indigo-600 font-semibold">
              <ShieldAlert className="w-4 h-4" />
              <span>SOC Incident Investigation Document</span>
            </div>
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">
              {report.investigation?.title || 'Security Incident Report'}
            </h1>
            <p className="text-xs text-slate-500">
              Generated on {report.generated_at ? report.generated_at.replace('T', ' ').slice(0, 19) : ''} UTC by {report.analyst}
            </p>
          </div>

          <div className="text-right">
            <span className="px-3 py-1 rounded-full bg-indigo-50 text-indigo-700 border border-indigo-200 font-mono text-xs font-semibold">
              ID: {id?.slice(0, 8)}
            </span>
          </div>
        </div>

        {/* Executive Summary */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
            <FileText className="w-4 h-4 text-indigo-600" />
            1. Executive Summary
          </h2>
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-800 leading-relaxed whitespace-pre-wrap font-sans">
            {report.executive_summary}
          </div>
        </div>

        {/* Investigation Parameters */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-sky-600" />
            2. Investigation Parameters
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
              <span className="text-slate-500 uppercase text-[10px]">Analyst Query</span>
              <p className="text-slate-900 font-sans font-medium">{report.investigation?.analyst_query}</p>
            </div>
            <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
              <span className="text-slate-500 uppercase text-[10px]">Telemetry Match Count</span>
              <p className="text-emerald-700 font-bold">{report.investigation?.total_events_matched} security log events</p>
            </div>
          </div>
        </div>

        {/* IOC Section */}
        {report.iocs && report.iocs.length > 0 && (
          <div className="space-y-3">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
              <Key className="w-4 h-4 text-emerald-600" />
              3. Extracted Indicators of Compromise (IOCs)
            </h2>
            <IOCPanel iocs={report.iocs} />
          </div>
        )}

        {/* MITRE ATT&CK Mapping */}
        {report.attack_analysis?.mitre_techniques && report.attack_analysis.mitre_techniques.length > 0 && (
          <div className="space-y-3">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
              <Target className="w-4 h-4 text-purple-600" />
              4. MITRE ATT&CK Classification
            </h2>
            <MitreCard techniques={report.attack_analysis.mitre_techniques} />
          </div>
        )}

        {/* Attack Timeline */}
        {report.timeline?.events && report.timeline.events.length > 0 && (
          <div className="space-y-3">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
              <Clock className="w-4 h-4 text-amber-600" />
              5. Chronological Attack Timeline
            </h2>
            <TimelineView events={report.timeline.events} summary={report.timeline.summary} />
          </div>
        )}

        {/* Evidence Logs Table */}
        {report.evidence && report.evidence.length > 0 && (
          <div className="space-y-3">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
              <Activity className="w-4 h-4 text-sky-600" />
              6. Security Log Evidence
            </h2>
            <div className="rounded-lg border border-slate-200 overflow-hidden bg-white text-xs shadow-xs">
              <div className="max-h-60 overflow-y-auto">
                <table className="w-full text-left">
                  <thead className="bg-slate-50 text-slate-600 font-mono text-[10px] sticky top-0 border-b border-slate-200">
                    <tr>
                      <th className="p-2.5">Timestamp</th>
                      <th className="p-2.5">Source IP</th>
                      <th className="p-2.5">User</th>
                      <th className="p-2.5">Action</th>
                      <th className="p-2.5">HTTP</th>
                      <th className="p-2.5">URL</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 font-mono text-slate-700 text-[11px]">
                    {report.evidence.map((ev, i) => (
                      <tr key={i} className="hover:bg-indigo-50/40">
                        <td className="p-2.5 text-slate-500">{ev.timestamp ? ev.timestamp.replace('T', ' ').slice(0, 19) : '-'}</td>
                        <td className="p-2.5 text-indigo-600 font-semibold">{ev.source_ip}</td>
                        <td className="p-2.5 text-amber-700 font-semibold">{ev.username || '-'}</td>
                        <td className="p-2.5 text-slate-800">{ev.event_action?.replace(/_/g, ' ')}</td>
                        <td className="p-2.5">{ev.http_status || '-'}</td>
                        <td className="p-2.5 text-slate-600 truncate max-w-xs">{ev.url || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* AI Recommendations */}
        {report.recommendations && report.recommendations.length > 0 && (
          <div className="space-y-3">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              7. Remediation Recommendations
            </h2>
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2 text-xs">
              {report.recommendations.map((rec, i) => (
                <div key={i} className="flex items-start gap-2 text-slate-800">
                  <span className="text-emerald-700 font-bold font-mono">{i + 1}.</span>
                  <span>{rec}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );

};
