import React from 'react';
import { IOC } from '../../types';
import { Network, User, Globe, Hash, ShieldAlert, Key } from 'lucide-react';

interface IOCPanelProps {
  iocs: IOC[];
}

export const IOCPanel: React.FC<IOCPanelProps> = ({ iocs }) => {
  if (!iocs || iocs.length === 0) {
    return (
      <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-500 italic text-center">
        No indicators of compromise (IOCs) identified in this evidence window.
      </div>
    );
  }

  const getIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'ipv4':
      case 'ipv6':
        return <Network className="w-3.5 h-3.5 text-sky-600" />;
      case 'username':
        return <User className="w-3.5 h-3.5 text-amber-600" />;
      case 'domain':
      case 'url':
        return <Globe className="w-3.5 h-3.5 text-emerald-600" />;
      case 'hash_md5':
      case 'hash_sha256':
        return <Hash className="w-3.5 h-3.5 text-purple-600" />;
      default:
        return <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />;
    }
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center gap-1.5">
          <Key className="w-3.5 h-3.5 text-indigo-600" />
          Extracted IOCs ({iocs.length})
        </h4>
      </div>

      <div className="flex flex-wrap gap-2 max-h-48 overflow-y-auto p-1">
        {iocs.map((ioc, idx) => (
          <div
            key={idx}
            className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono group hover:border-slate-300 transition-colors shadow-2xs"
          >
            {getIcon(ioc.type)}
            <span className="text-slate-800 font-semibold">{ioc.value}</span>
            <span className="px-1.5 py-0.2 rounded bg-white text-slate-600 border border-slate-200 text-[10px]">
              {ioc.occurrence_count}x
            </span>
            {ioc.is_internal && (
              <span className="px-1 py-0.2 rounded bg-sky-50 text-sky-700 text-[9px] border border-sky-200 font-semibold">
                Internal
              </span>
            )}
            {ioc.flagged && (
              <span className="px-1 py-0.2 rounded bg-rose-50 text-rose-700 text-[9px] border border-rose-200 font-semibold">
                Suspicious
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

