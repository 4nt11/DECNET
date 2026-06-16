// SPDX-License-Identifier: AGPL-3.0-or-later
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';

export const API_BASE = 'http://localhost:8000/api/v1';

export const server = setupServer();

export { http, HttpResponse };

export const apiUrl = (path: string): string => {
  const trimmed = path.startsWith('/') ? path : `/${path}`;
  return `${API_BASE}${trimmed}`;
};
