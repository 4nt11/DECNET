import React, { useEffect, useRef } from 'react';
import { X, type LucideIcon } from '../../icons';
import { useEscapeKey } from '../../hooks/useEscapeKey';
import { useFocusTrap } from '../../hooks/useFocusTrap';
import './Modal.css';

interface Props {
  open: boolean;
  onClose: () => void;
  title?: string;
  icon?: LucideIcon;
  footer?: React.ReactNode;
  accent?: 'matrix' | 'violet';
  width?: 'default' | 'wide';
  variant?: 'center' | 'drawer-right';
  children: React.ReactNode;
  className?: string;
}

const Modal: React.FC<Props> = ({
  open,
  onClose,
  title,
  icon: Icon,
  footer,
  accent = 'matrix',
  width = 'default',
  variant = 'center',
  children,
  className = '',
}) => {
  const panelRef = useRef<HTMLDivElement | null>(null);

  useEscapeKey(onClose, open);
  useFocusTrap(panelRef, open);

  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = prev;
    };
  }, [open]);

  if (!open) return null;

  const panelClasses = [
    'modal',
    accent === 'violet' ? 'violet' : '',
    width === 'wide' ? 'wide' : '',
    variant === 'drawer-right' ? 'modal-drawer-right' : '',
    className,
  ].filter(Boolean).join(' ');

  const backdropClass = variant === 'drawer-right' ? 'modal-backdrop drawer' : 'modal-backdrop';

  return (
    <div className={backdropClass} onClick={onClose}>
      <div
        ref={panelRef}
        className={panelClasses}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        {title && (
          <div className="modal-head">
            <h3>
              {Icon && <Icon size={14} />}
              {title}
            </h3>
            <button className="close-btn" onClick={onClose} aria-label="Close">
              <X size={16} />
            </button>
          </div>
        )}
        {children}
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
};

export default Modal;
