import React, { useEffect, useState } from 'react';
import { 
  Shield, 
  Activity, 
  Key, 
  Lock, 
  Target, 
  Layers, 
  FileText, 
  Server, 
  AlertTriangle,
  ArrowUpRight 
} from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell 
} from 'recharts';
import { dashboardApi } from '../api/client';
import { DashboardStats } from '../types';
import { Link } from 'react-router-dom';


const COLORS = ['#6366F1', '#8B5CF6', '#EC4899', '#F43F5E', '#10B981', '#F59E0B'];

export const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const data = await dashboardApi.getStats();
        setStats(data);
      } catch (err) {
        console.error('Failed to load dashboard metrics:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchStats();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-slate-400 text-xs flex items-center gap-2">
          <Activity className="w-4 h-4 animate-spin text-indigo-500" />
          <span>Aggregating SIEM metrics & telemetry...</span>
        </div>
      </div>
    );
  }

  const statCards = [
    {
      title: 'Total Investigations',
      value: stats?.total_investigations || 0,
      icon: Activity,
      color: 'text-indigo-600',
      bgColor: 'bg-indigo-50 border-indigo-200',
    },
    {
      title: 'IOCs Extracted',
      value: stats?.total_iocs || 0,
      icon: Key,
      color: 'text-emerald-600',
      bgColor: 'bg-emerald-50 border-emerald-200',
    },
    {
      title: 'MITRE ATT&CK Mappings',
      value: stats?.total_mitre_techniques || 0,
      icon: Target,
      color: 'text-purple-600',
      bgColor: 'bg-purple-50 border-purple-200',
    },
    {
      title: 'Failed Logins Tracked',
      value: stats?.failed_login_count || 0,
      icon: Lock,
      color: 'text-amber-600',
      bgColor: 'bg-amber-50 border-amber-200',
    },
  ];

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Top Stat Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((card, i) => {
          const Icon = card.icon;
          return (
            <div
              key={i}
              className="p-5 rounded-xl bg-white border border-slate-200 flex items-center justify-between shadow-xs"
            >
              <div className="space-y-1">
                <p className="text-xs font-semibold text-slate-500">{card.title}</p>
                <p className="text-2xl font-bold text-slate-900 font-mono">{card.value}</p>
              </div>
              <div className={`p-3 rounded-xl border ${card.bgColor} ${card.color}`}>
                <Icon className="w-5 h-5" />
              </div>
            </div>
          );
        })}
      </div>

      {/* Charts section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Attacking IPs Bar Chart */}
        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-4 shadow-xs">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
              <Server className="w-4 h-4 text-sky-600" />
              Top Source IPs by Event Volume
            </h3>
          </div>

          <div className="h-64">
            {stats?.top_source_ips && stats.top_source_ips.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.top_source_ips} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                  <XAxis dataKey="ip" stroke="#64748B" fontSize={10} angle={-30} textAnchor="end" />
                  <YAxis stroke="#64748B" fontSize={10} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', color: '#0f172a', fontSize: '11px', borderRadius: '8px' }}
                    itemStyle={{ color: '#4f46e5' }}
                  />
                  <Bar dataKey="count" fill="#6366F1" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-xs text-slate-500 italic">
                No telemetry data yet. Run an investigation to populate metrics.
              </div>
            )}
          </div>
        </div>

        {/* MITRE ATT&CK Breakdown */}
        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-4 shadow-xs">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
              <Target className="w-4 h-4 text-purple-600" />
              MITRE ATT&CK Technique Distribution
            </h3>
          </div>

          <div className="h-64 flex items-center justify-center">
            {stats?.top_mitre_techniques && stats.top_mitre_techniques.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={stats.top_mitre_techniques}
                    dataKey="count"
                    nameKey="technique_name"
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    label={({ name }) => name}
                  >
                    {stats.top_mitre_techniques.map((_, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', color: '#0f172a', fontSize: '11px', borderRadius: '8px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-xs text-slate-500 italic">
                No techniques mapped yet. Run an investigation to map behaviors.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Investigations Table */}
      <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-4 shadow-xs">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
            <FileText className="w-4 h-4 text-indigo-600" />
            Recent Threat Investigations
          </h3>
          <Link to="/history" className="text-xs text-indigo-600 hover:text-indigo-700 font-semibold flex items-center gap-1">
            <span>View All</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-600 font-mono text-[11px] border-b border-slate-200">
              <tr>
                <th className="py-2.5 px-3">Investigation ID</th>
                <th className="py-2.5 px-3">Analyst Query</th>
                <th className="py-2.5 px-3">Events Found</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono text-slate-700 text-[11px]">
              {stats?.recent_investigations && stats.recent_investigations.length > 0 ? (
                stats.recent_investigations.map((inv) => (
                  <tr key={inv.id} className="hover:bg-indigo-50/30 transition-colors">
                    <td className="py-2.5 px-3 text-indigo-600 font-bold">{inv.id.slice(0, 8)}</td>
                    <td className="py-2.5 px-3 font-sans text-slate-800 font-medium">{inv.query}</td>
                    <td className="py-2.5 px-3 text-slate-600">{inv.result_count}</td>
                    <td className="py-2.5 px-3">
                      <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 text-[10px] font-semibold">
                        {inv.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-500">
                      {inv.created_at ? inv.created_at.slice(0, 16).replace('T', ' ') : '-'}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="py-6 text-center text-slate-500 italic">
                    No past investigations recorded. Start asking security questions in the Copilot!
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );

};
