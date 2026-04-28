import React from 'react';
import type { LucideIcon } from '../../icons';
import './EmptyState.css';

interface CTA {
  label: string;
  onClick: () => void;
  icon?: LucideIcon;
}

interface Props {
  icon?: LucideIcon;
  title: string;
  hint?: string;
  cta?: CTA;
  size?: 'default' | 'compact';
  className?: string;
}

const EmptyState: React.FC<Props> = ({ icon: Icon, title, hint, cta, size = 'default', className = '' }) => {
  if (size === 'compact') {
    return (
      <div className={`empty-state empty-state-compact ${className}`}>
        {Icon && <Icon size={12} />}
        <span>{title}</span>
      </div>
    );
  }

  const CtaIcon = cta?.icon;
  return (
    <div className={`empty-state ${className}`}>
      {Icon && <Icon size={28} className="empty-state-icon" />}
      <div className="type-label empty-state-title">{title}</div>
      {hint && <div className="empty-state-hint">{hint}</div>}
      {cta && (
        <button type="button" className="empty-state-cta" onClick={cta.onClick}>
          {CtaIcon && <CtaIcon size={12} />}
          <span>{cta.label}</span>
        </button>
      )}
    </div>
  );
};

export default EmptyState;
