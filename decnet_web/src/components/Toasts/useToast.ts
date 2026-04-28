import { useContext } from 'react';
import { ToastContext } from './toast-context';
import type { ToastContextValue } from './toast-context';

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used inside <ToastProvider>');
  return ctx;
}
