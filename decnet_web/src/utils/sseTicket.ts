// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * SSE ticket helper — mints a single-use opaque ticket for authenticating
 * an EventSource connection.  Native EventSource cannot set an Authorization
 * header, so the backend issues a short-lived (?60 s) ticket via a normal
 * Bearer-authenticated REST call and the ticket is passed as ?ticket= on
 * the stream URL.
 *
 * IMPORTANT: the ticket is SINGLE-USE.  Mint a fresh ticket for every
 * connection attempt — initial connect AND every reconnect.
 */
import api from './api';

/**
 * POST /auth/sse-ticket with the normal Bearer JWT (attached automatically
 * by the axios `api` instance) and return the opaque ticket string.
 *
 * Throws if the API call fails (e.g. 401 when the JWT has expired).
 * Callers are responsible for handling the error — typically by invoking
 * their existing onError handler and scheduling a reconnect, which will
 * cause the axios 401 interceptor to fire `auth:logout`.
 */
export async function mintSseTicket(): Promise<string> {
  const res = await api.post<{ ticket: string; expires_in: number }>('/auth/sse-ticket');
  return res.data.ticket;
}
