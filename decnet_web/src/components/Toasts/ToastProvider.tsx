// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useCallback, useEffect, useRef, useState } from 'react';
import Toasts from './Toasts';
import { ToastContext } from './toast-context';
import type { Toast, ToastInput } from './toast-context';

const DISMISS_MS = 3200;

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [items, setItems] = useState<Toast[]>([]);
  const timers = useRef<Map<number, ReturnType<typeof setTimeout>>>(new Map());

  const push = useCallback((t: ToastInput) => {
    const id = Date.now() + Math.random();
    setItems(prev => [...prev, { ...t, id }]);
    const timer = setTimeout(() => {
      setItems(prev => prev.filter(x => x.id !== id));
      timers.current.delete(id);
    }, DISMISS_MS);
    timers.current.set(id, timer);
  }, []);

  useEffect(() => {
    const map = timers.current;
    return () => { map.forEach(clearTimeout); map.clear(); };
  }, []);

  return (
    <ToastContext.Provider value={{ push }}>
      {children}
      <Toasts items={items} />
    </ToastContext.Provider>
  );
};
