import React from 'react';
import {
  CheckCircle, RefreshCw, Download, Upload, Pause, Play, AlertTriangle,
  Info, Terminal, Activity, ShieldAlert,
} from '../../icons';
import type { Toast } from './toast-context';
import './Toasts.css';

const ICON_MAP: Record<string, React.ComponentType<{ size?: number }>> = {
  'check-circle': CheckCircle,
  'refresh-cw': RefreshCw,
  'download': Download,
  'upload': Upload,
  'pause': Pause,
  'play': Play,
  'alert-triangle': AlertTriangle,
  'info': Info,
  'terminal': Terminal,
  'activity': Activity,
  'shield-alert': ShieldAlert,
};

interface Props {
  items: Toast[];
}

const Toasts: React.FC<Props> = ({ items }) => {
  if (items.length === 0) return null;
  return (
    <div className="toast-stack">
      {items.map(t => {
        const Icon = ICON_MAP[t.icon ?? 'check-circle'] ?? CheckCircle;
        return (
          <div key={t.id} className={`toast ${t.tone ?? ''}`.trim()}>
            <Icon size={14} />
            <span>{t.text}</span>
          </div>
        );
      })}
    </div>
  );
};

export default Toasts;
