import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Users, 
  HardDrive, 
  Cpu, 
  Activity, 
  Database,
  RefreshCw,
  AlertTriangle
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

interface SOCUser {
  name: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
  status: 'active' | 'suspended';
}

export const AdminSettings: React.FC = () => {
  const { user } = useAuth();
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [successMsg, setSuccessMsg] = useState('');

  // Pre-seeded/mock list of users for display in admin panel
  const [users, setUsers] = useState<SOCUser[]>([
    { name: 'SOC Administrator', email: 'admin@soc.corp', role: 'admin', status: 'active' },
    { name: 'Senior SOC Analyst', email: 'analyst@soc.corp', role: 'analyst', status: 'active' },
    { name: 'Security Auditor', email: 'viewer@soc.corp', role: 'viewer', status: 'active' }
  ]);

  const handleSimulateAction = (action: string) => {
    setIsRefreshing(true);
    setSuccessMsg('');
    setTimeout(() => {
      setIsRefreshing(false);
      setSuccessMsg(`Successfully executed action: ${action}`);
    }, 1200);
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Top Banner */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-2xl text-white relative overflow-hidden shadow-lg">
        <div className="absolute top-0 right-0 w-80 h-80 bg-rose-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div className="flex items-center gap-4 relative z-10">
          <div className="p-3 bg-rose-500/20 text-rose-400 rounded-xl border border-rose-500/30">
            <ShieldCheck className="w-8 h-8" />
          </div>
          <div>
            <h2 className="text-xl font-bold tracking-tight">SOC Administrative Console</h2>
            <p className="text-xs text-slate-400">
              System-wide security settings, log pipelines state, and role management permissions.
            </p>
          </div>
        </div>
      </div>

      {successMsg && (
        <div className="p-3 bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs rounded-xl flex items-center gap-2">
          <Activity className="w-4 h-4 text-emerald-600 animate-pulse" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Grid of System Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs flex items-center gap-4">
          <div className="p-2.5 bg-slate-100 text-slate-700 rounded-lg">
            <Users className="w-5 h-5" />
          </div>
          <div>
            <p className="text-[10px] uppercase font-bold tracking-wider text-slate-400">Active Profiles</p>
            <h3 className="text-lg font-bold text-slate-800">{users.length} SOC Users</h3>
          </div>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs flex items-center gap-4">
          <div className="p-2.5 bg-slate-100 text-slate-700 rounded-lg">
            <Database className="w-5 h-5 text-indigo-600" />
          </div>
          <div>
            <p className="text-[10px] uppercase font-bold tracking-wider text-slate-400">Mock Database</p>
            <h3 className="text-lg font-bold text-slate-800">5,000 ECS Logs</h3>
          </div>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs flex items-center gap-4">
          <div className="p-2.5 bg-slate-100 text-slate-700 rounded-lg">
            <Cpu className="w-5 h-5 text-emerald-600" />
          </div>
          <div>
            <p className="text-[10px] uppercase font-bold tracking-wider text-slate-400">Memory usage</p>
            <h3 className="text-lg font-bold text-slate-800">48.2 MB / 1% CPU</h3>
          </div>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs flex items-center gap-4">
          <div className="p-2.5 bg-slate-100 text-slate-700 rounded-lg">
            <HardDrive className="w-5 h-5 text-amber-600" />
          </div>
          <div>
            <p className="text-[10px] uppercase font-bold tracking-wider text-slate-400">System health</p>
            <h3 className="text-lg font-bold text-slate-800">Operational</h3>
          </div>
        </div>
      </div>

      {/* Main Admin Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* User Role Matrix */}
        <div className="lg:col-span-2 bg-white rounded-xl border border-slate-200 shadow-xs p-6 space-y-4">
          <h3 className="text-sm font-bold text-slate-900">User Identity & Privilege Matrix</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-100 text-slate-400 uppercase tracking-wider text-[10px] font-bold">
                  <th className="pb-3">Name</th>
                  <th className="pb-3">Email Address</th>
                  <th className="pb-3">Access Level</th>
                  <th className="pb-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-slate-700 font-mono">
                {users.map((u, i) => (
                  <tr key={i} className="hover:bg-slate-50/50">
                    <td className="py-3.5 font-sans font-semibold text-slate-900">{u.name}</td>
                    <td className="py-3.5">{u.email}</td>
                    <td className="py-3.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        u.role === 'admin' ? 'bg-rose-50 text-rose-700 border border-rose-100' :
                        u.role === 'analyst' ? 'bg-indigo-50 text-indigo-700 border border-indigo-100' :
                        'bg-slate-100 text-slate-700 border border-slate-200'
                      }`}>
                        {u.role}
                      </span>
                    </td>
                    <td className="py-3.5">
                      <span className="flex items-center gap-1.5 text-[11px] font-sans">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                        {u.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Admin Controls */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-xs p-6 space-y-6">
          <div>
            <h3 className="text-sm font-bold text-slate-900 mb-1.5">Administrative Pipelines</h3>
            <p className="text-xs text-slate-500 leading-relaxed">
              Flush caches or rebuild elasticsearch mock templates. These actions affect global operations.
            </p>
          </div>

          <div className="space-y-3">
            <button
              onClick={() => handleSimulateAction('Flush query plan cache')}
              disabled={isRefreshing}
              className="w-full py-2.5 px-4 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-lg text-xs font-semibold text-slate-700 hover:text-slate-950 transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-indigo-600 ${isRefreshing ? 'animate-spin' : ''}`} />
              <span>Flush Query Plan Cache</span>
            </button>

            <button
              onClick={() => handleSimulateAction('Reseed mock datasets')}
              disabled={isRefreshing}
              className="w-full py-2.5 px-4 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-lg text-xs font-semibold text-slate-700 hover:text-slate-950 transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <Database className="w-3.5 h-3.5 text-emerald-600" />
              <span>Reseed Mock SIEM Dataset</span>
            </button>
          </div>

          <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-[10px] text-amber-900 flex gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
            <div>
              <span className="font-bold">Production Warning:</span> Switching to <code className="bg-amber-100 px-1 py-0.5 rounded font-mono">elasticsearch</code> mode requires configuring credentials in the host environment.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
