// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { LLMTab } from './LLMTab';
import { renderWithRouter } from '../../../test/renderWithRouter';

vi.mock('../../../utils/api', () => ({
  default: { get: vi.fn(), put: vi.fn() },
}));

import api from '../../../utils/api';
const apiGet = api.get as ReturnType<typeof vi.fn>;
const apiPut = api.put as ReturnType<typeof vi.fn>;

const defaultPayload = {
  provider: 'ollama',
  base_url: null,
  model: 'llama3.1',
  timeout: 60,
  api_key_set: false,
};

const render = (isAdmin = true) =>
  renderWithRouter(<LLMTab isAdmin={isAdmin} />);

describe('LLMTab', () => {
  beforeEach(() => {
    apiGet.mockReset();
    apiPut.mockReset();
  });

  it('renders current model after load', async () => {
    apiGet.mockResolvedValueOnce({ data: defaultPayload });
    render();
    await waitFor(() => expect(screen.queryByText('LOADING…')).toBeNull());
    expect(screen.getByDisplayValue('llama3.1')).toBeDefined();
  });

  it('shows key-stored indicator when api_key_set is true', async () => {
    apiGet.mockResolvedValueOnce({ data: { ...defaultPayload, api_key_set: true } });
    render();
    await waitFor(() => expect(screen.queryByText('LOADING…')).toBeNull());
    expect(screen.getByText(/KEY SET/)).toBeDefined();
  });

  it('calls PUT on save and shows success', async () => {
    apiGet.mockResolvedValueOnce({ data: defaultPayload });
    apiPut.mockResolvedValueOnce({ data: { ...defaultPayload, model: 'phi3' } });

    const user = userEvent.setup();
    render();
    await waitFor(() => expect(screen.queryByText('LOADING…')).toBeNull());

    const modelInput = screen.getByDisplayValue('llama3.1');
    await user.clear(modelInput);
    await user.type(modelInput, 'phi3');
    await user.click(screen.getByRole('button', { name: /SAVE/ }));

    await waitFor(() => expect(screen.getByText('LLM CONFIG SAVED')).toBeDefined());
    const [url, body] = apiPut.mock.calls[0];
    expect(url).toBe('/realism/llm');
    expect(body.model).toBe('phi3');
  });

  it('shows error on 403', async () => {
    apiGet.mockResolvedValueOnce({ data: defaultPayload });
    apiPut.mockRejectedValueOnce({ response: { status: 403 } });

    const user = userEvent.setup();
    render();
    await waitFor(() => expect(screen.queryByText('LOADING…')).toBeNull());
    await user.click(screen.getByRole('button', { name: /SAVE/ }));

    await waitFor(() => expect(screen.getByText(/Admin role required/)).toBeDefined());
  });

  it('hides save button for viewers', async () => {
    apiGet.mockResolvedValueOnce({ data: defaultPayload });
    render(false);
    await waitFor(() => expect(screen.queryByText('LOADING…')).toBeNull());
    expect(screen.queryByRole('button', { name: /SAVE/ })).toBeNull();
  });

  it('sends empty api_key to clear when CLEAR button used', async () => {
    apiGet.mockResolvedValueOnce({ data: { ...defaultPayload, api_key_set: true } });
    apiPut.mockResolvedValueOnce({ data: { ...defaultPayload, api_key_set: false } });

    const user = userEvent.setup();
    render();
    await waitFor(() => expect(screen.queryByText('LOADING…')).toBeNull());

    await user.click(screen.getByRole('button', { name: /CLEAR/ }));
    await user.click(screen.getByRole('button', { name: /SAVE/ }));

    await waitFor(() => expect(apiPut).toHaveBeenCalledOnce());
    const [, body] = apiPut.mock.calls[0];
    expect(body.api_key).toBe('');
  });
});
