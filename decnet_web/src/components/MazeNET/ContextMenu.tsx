// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useRef, useState } from 'react';
import { ChevronRight } from '../../icons';

export interface MenuItem {
  label: string;
  onClick?: () => void;
  disabled?: boolean;
  title?: string;
  danger?: boolean;
  separator?: boolean;
  icon?: React.ReactNode;
  submenu?: MenuItem[];
}

interface Props {
  x: number;
  y: number;
  items: MenuItem[];
  onClose: () => void;
  title?: string;
}

const ContextMenu: React.FC<Props> = ({ x, y, items, onClose, title }) => {
  const ref = useRef<HTMLDivElement>(null);
  const [openSub, setOpenSub] = useState<number | null>(null);

  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('mousedown', onDown);
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('mousedown', onDown);
      window.removeEventListener('keydown', onKey);
    };
  }, [onClose]);

  const renderItem = (it: MenuItem, i: number) => {
    if (it.separator) return <div key={i} className="ctx-divider" />;
    const hasSub = !!it.submenu?.length;
    return (
      <div
        key={i}
        className="ctx-item-wrap"
        onMouseEnter={() => setOpenSub(hasSub ? i : null)}
      >
        <button
          type="button"
          className={`ctx-item ${it.danger ? 'danger' : ''}`}
          disabled={it.disabled}
          title={it.title}
          onClick={() => {
            if (it.disabled) return;
            if (hasSub) return;
            it.onClick?.();
            onClose();
          }}
        >
          {it.icon && <span className="ctx-icon">{it.icon}</span>}
          <span className="ctx-label">{it.label}</span>
          {hasSub && <ChevronRight size={12} className="ctx-chev" />}
        </button>
        {hasSub && openSub === i && (
          <div className="ctx-submenu">
            {it.submenu!.map((s, j) =>
              s.separator ? (
                <div key={j} className="ctx-divider" />
              ) : (
                <button
                  key={j}
                  type="button"
                  className={`ctx-item ${s.danger ? 'danger' : ''}`}
                  disabled={s.disabled}
                  title={s.title}
                  onClick={() => { if (!s.disabled) { s.onClick?.(); onClose(); } }}
                >
                  {s.icon && <span className="ctx-icon">{s.icon}</span>}
                  <span className="ctx-label">{s.label}</span>
                </button>
              ),
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div ref={ref} className="ctx-menu" style={{ left: x, top: y }}>
      {title && <div className="ctx-title">{title}</div>}
      {items.map(renderItem)}
    </div>
  );
};

export default ContextMenu;
