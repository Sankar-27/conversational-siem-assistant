import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  ShieldAlert, 
  MessageSquareCode, 
  LayoutDashboard, 
  History, 
  FileText, 
  Terminal, 
  Database,
  Lock,
  Settings
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export const Sidebar: React.FC = () => {
  const { user } = useAuth();

  const navItems = [
    { to: '/chat', label: 'Investigation Copilot', icon: MessageSquareCode },
    { to: '/dashboard', label: 'Security Dashboard', icon: LayoutDashboard },
    { to: '/history', label: 'Investigation History', icon: History },
  ];

  const getRoleBadgeClass = (role?: string) => {
    const r = role?.toLowerCase() || 'analyst';
    if (r === 'admin') return 'bg-rose-50 text-rose-700 border-rose-200/60';
    if (r === 'viewer') return 'bg-slate-100 text-slate-600 border-slate-200';
    return 'bg-indigo-50 text-indigo-700 border-indigo-200/60';
  };

  return (
    <aside className="w-64 bg-white border-r border-slate-200 flex flex-col justify-between shrink-0 h-screen sticky top-0 shadow-sm">
      <div>
        {/* Brand header */}
        <div className="h-16 flex items-center gap-3 px-6 border-b border-slate-200 bg-slate-50/50">
          <div className="p-2 rounded-lg bg-indigo-50 text-indigo-600 border border-indigo-200/60 shadow-sm">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <h1 className="font-bold text-sm tracking-tight text-slate-900 flex items-center gap-1.5">
              SIEM COPILOT <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-50 text-indigo-700 font-mono border border-indigo-200 font-semibold">v1.0</span>
            </h1>
            <p className="text-[11px] text-slate-500 font-medium">Conversational Threat Intel</p>
          </div>
        </div>

        {/* Navigation list */}
        <nav className="p-4 space-y-1.5">
          <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 px-3 py-2">
            Operations
          </p>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-indigo-50 text-indigo-700 font-semibold border border-indigo-200/80 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100/70'
                  }`
                }
              >
                <Icon className="w-4 h-4" />
                <span>{item.label}</span>
              </NavLink>
            );
          })}

          {user?.role === 'admin' && (
            <NavLink
              to="/admin-settings"
              className={({ isActive }) =>
                `flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-rose-50 text-rose-700 font-semibold border border-rose-200/80 shadow-xs'
                    : 'text-slate-600 hover:text-rose-900 hover:bg-slate-100/70'
                }`
              }
            >
              <Settings className="w-4 h-4 text-rose-600" />
              <span>Admin Settings</span>
            </NavLink>
          )}

          <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 px-3 pt-6 pb-2">
            SIEM Telemetry
          </p>
          <div className="px-3.5 py-3 rounded-lg bg-slate-50 border border-slate-200 space-y-2 text-xs">
            <div className="flex items-center justify-between text-slate-600 text-[11px]">
              <span className="flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5 text-emerald-600" />
                SIEM Mode
              </span>
              <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 font-mono border border-emerald-200 text-[10px] font-semibold">
                Mock / ES
              </span>
            </div>
            <div className="flex items-center justify-between text-slate-600 text-[11px]">
              <span className="flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-indigo-600" />
                Log Schema
              </span>
              <span className="font-mono text-slate-700 text-[10px] font-semibold">ECS Normalized</span>
            </div>
          </div>
        </nav>
      </div>

      {/* User profile card */}
      <div className="p-4 border-t border-slate-200 bg-slate-50/50">
        <div className="flex items-center gap-3 px-2 py-1.5">
          <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-indigo-600 to-violet-600 flex items-center justify-center font-bold text-xs text-white uppercase shadow-sm">
            {user?.name?.slice(0, 2) || 'SA'}
          </div>
          <div className="overflow-hidden">
            <p className="text-xs font-semibold text-slate-900 truncate">{user?.name || 'Security Analyst'}</p>
            <p className="text-[11px] text-slate-500 flex items-center gap-1 mt-0.5">
              <span className={`px-1.5 py-0.5 rounded border text-[9px] font-bold uppercase tracking-wider ${getRoleBadgeClass(user?.role)}`}>
                {user?.role || 'analyst'}
              </span>
            </p>
          </div>
        </div>
      </div>
    </aside>
  );
};

