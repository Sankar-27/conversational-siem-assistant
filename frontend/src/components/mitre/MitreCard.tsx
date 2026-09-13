import React from 'react';
import { MITRETechnique } from '../../types';
import { Shield, ExternalLink, Target } from 'lucide-react';

interface MitreCardProps {
  techniques: MITRETechnique[];
}

export const MitreCard: React.FC<MitreCardProps> = ({ techniques }) => {
  if (!techniques || techniques.length === 0) {
    return (
      <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-500 italic text-center">
        No MITRE ATT&CK techniques mapped for this event cluster.
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center gap-1.5">
          <Target className="w-3.5 h-3.5 text-purple-600" />
          MITRE ATT&CK Mapping ({techniques.length})
        </h4>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {techniques.map((tech, idx) => {
          const confPercent = Math.round(tech.confidence * 100);
          return (
            <div
              key={idx}
              className="p-3.5 rounded-lg bg-white border border-purple-200 hover:border-purple-300 transition-all space-y-2 relative overflow-hidden group shadow-xs"
            >
              {/* Top bar info */}
              <div className="flex items-start justify-between gap-2">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-purple-50 text-purple-700 font-mono font-bold text-xs border border-purple-200">
                      {tech.technique_id}
                    </span>
                    <span className="text-xs font-bold text-slate-900 group-hover:text-purple-700 transition-colors">
                      {tech.technique_name}
                    </span>
                  </div>
                  <p className="text-[11px] text-purple-600 font-medium">Tactic: {tech.tactic}</p>
                </div>

                <a
                  href={`https://attack.mitre.org/techniques/${tech.technique_id}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-slate-400 hover:text-purple-600 transition-colors"
                  title="Open in MITRE ATT&CK Matrix"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
              </div>

              {/* Description */}
              <p className="text-slate-600 text-xs line-clamp-2 leading-relaxed">
                {tech.description}
              </p>

              {/* Confidence meter */}
              <div className="space-y-1 pt-1 border-t border-slate-100">
                <div className="flex items-center justify-between text-[10px] text-slate-500">
                  <span>Confidence Score</span>
                  <span className="font-mono font-bold text-purple-700">{confPercent}%</span>
                </div>
                <div className="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
                  <div
                    className="bg-gradient-to-r from-indigo-500 to-purple-600 h-1.5 rounded-full"
                    style={{ width: `${confPercent}%` }}
                  ></div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

