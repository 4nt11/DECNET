import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import LLMConfig from './LLMConfig';
import { renderWithRouter } from '../../test/renderWithRouter';

vi.mock('../../utils/api', () => ({
  default: { get: vi.fn(), put: vi.fn() },
}));

import api from '../../utils/api';
const apiGet = api.get as ReturnType<typeof vi.fn>;
const apiPut = api.put as ReturnType<typeof vi.fn>;

const defaultPayload = {
  provider: 'ollama',
  base_url: null,
  model: 'llama3.1',
  timeout: 60,
  api_key_set: false,
};

const renderPage = () => renderWithRouter(<LLMConfig />);

describe('LLMConfig', () => {
  beforeEach(() => {
    apiGet.mockReset();
    apiPut.mockReset();
  });

  it('renders provider and model from loaded config', async () => {
    apiGet.mockResolvedValueOnce({ data: defaultPayload });
    renderPage();
    await waitFor(() => expect(screen.queryByText('Loading…')).toBeNull());
    expect(screen.getByDisplayValue('Ollama')).toBeDefined();
    expect(screen.getByDisplayValue('llama3.1')).toBeDefined();
  });

  it('shows api_key_set indicator when key is stored', async () => {
    apiGet.mockResolvedValueOnce({
      data: { ...defaultPayload, api_key_set: true },
    });
    renderPage();
    await waitFor(() => expect(screen.queryByText('Loading…')).toBeNull());
    expect(screen.getByText(/KEY SET/)).toBeDefined();
  });

  it('shows password input when no key is stored', async () => {
    apiGet.mockResolvedValueOnce({ data: defaultPayload });
    renderPage();
    await waitFor(() => expect(screen.queryByText('Loading…')).toBeNull());
    const input = screen.getByPlaceholderText(/Enter key to set/);
    expect(input).toBeDefined();
  });

  it('calls PUT with correct body on save', async () => {
    apiGet.mockResolvedValueOnce({ data: defaultPayload });
    apiPut.mockResolvedValueOnce({
      data: { ...defaultPayload, model: 'phi3' },
    });

    const user = userEvent.setup();
    renderPage();
    await waitFor(() => expect(screen.queryByText('Loading…')).toBeNull());

    const modelInput = screen.getByDisplayValue('llama3.1');
    await user.clear(modelInput);
    await user.type(modelInput, 'phi3');

    await user.click(screen.getByRole('button', { name: /SAVE/ }));

    await waitFor(() => expect(apiPut).toHaveBeenCalledOnce());
    const [url, body] = apiPut.mock.calls[0];
    expect(url).toBe('/realism/llm');
    expect(body.model).toBe('phi3');
    expect(body.api_key).toBeUndefined();
  });

  it('includes api_key in PUT body when entered', async () => {
    apiGet.mockResolvedValueOnce({ data: defaultPayload });
    apiPut.mockResolvedValueOnce({
      data: { ...defaultPayload, api_key_set: true },
    });

    const user = userEvent.setup();
    renderPage();
    await waitFor(() => expect(screen.queryByText('Loading…')).toBeNull());

    const keyInput = screen.getByPlaceholderText(/Enter key to set/);
    await user.type(keyInput, 'sk-secret');

    await user.click(screen.getByRole('button', { name: /SAVE/ }));

    await waitFor(() => expect(apiPut).toHaveBeenCalledOnce());
    const [, body] = apiPut.mock.calls[0];
    expect(body.api_key).toBe('sk-secret');
  });

  it('sends api_key="" when CLEAR is clicked', async () => {
    apiGet.mockResolvedValueOnce({
      data: { ...defaultPayload, api_key_set: true },
    });
    apiPut.mockResolvedValueOnce({
      data: { ...defaultPayload, api_key_set: false },
    });

    const user = userEvent.setup();
    renderPage();
    await waitFor(() => expect(screen.queryByText('Loading…')).toBeNull());

    await user.click(screen.getByRole('button', { name: /CLEAR/ }));
    await user.click(screen.getByRole('button', { name: /SAVE/ }));

    await waitFor(() => expect(apiPut).toHaveBeenCalledOnce());
    const [, body] = apiPut.mock.calls[0];
    expect(body.api_key).toBe('');
  });

  it('shows error when save returns 403', async () => {
    apiGet.mockResolvedValueOnce({ data: defaultPayload });
    apiPut.mockRejectedValueOnce({ response: { status: 403 } });

    const user = userEvent.setup();
    renderPage();
    await waitFor(() => expect(screen.queryByText('Loading…')).toBeNull());

    await user.click(screen.getByRole('button', { name: /SAVE/ }));

    await waitFor(() =>
      expect(screen.getByText(/Admin role required/)).toBeDefined(),
    );
  });
});
