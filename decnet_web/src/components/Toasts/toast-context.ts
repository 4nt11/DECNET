// SPDX-License-Identifier: AGPL-3.0-or-later
import { createContext } from 'react';

export type ToastTone = 'matrix' | 'violet' | 'alert';

export interface ToastInput {
  text: string;
  icon?: string;
  tone?: ToastTone;
}

export interface Toast extends ToastInput {
  id: number;
}

export interface ToastContextValue {
  push: (t: ToastInput) => void;
}

export const ToastContext = createContext<ToastContextValue | null>(null);
