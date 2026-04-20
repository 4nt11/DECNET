import React, { useEffect, useRef } from 'react';

export interface MenuItem {
  label: string;
  onClick?: () => void;
  disabled?: boolean;
  title?: string;
  danger?: boolean;
  separator?: boolean;
}

interface Props {
  x: number;
  y: number;
  items: MenuItem[];
  onClose: () => void;
}

const ContextMenu: React.FC<Props> = ({ x, y, items, onClose }) => {
  const ref = useRef<HTMLDivElement>(null);

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

  return (
    <div ref={ref} className="ctx-menu" style={{ left: x, top: y }}>
      {items.map((it, i) =>
        it.separator ? (
          <div key={i} className="ctx-divider" />
        ) : (
          <button
            key={i}
            type="button"
            className={`ctx-item ${it.danger ? 'danger' : ''}`}
            disabled={it.disabled}
            title={it.title}
            onClick={() => { if (!it.disabled) { it.onClick?.(); onClose(); } }}
          >
            {it.label}
          </button>
        ),
      )}
    </div>
  );
};

export default ContextMenu;
