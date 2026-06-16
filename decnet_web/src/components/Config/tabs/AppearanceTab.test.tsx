// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, beforeEach } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithRouter } from '../../../test/renderWithRouter';
import { AppearanceTab } from './AppearanceTab';

beforeEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute('data-accent');
});

describe('AppearanceTab', () => {
  it('starts with the matrix accent by default', () => {
    renderWithRouter(<AppearanceTab />);
    expect(screen.getByText('● MATRIX')).toBeInTheDocument();
    expect(screen.getByText('○ VIOLET')).toBeInTheDocument();
  });

  it('reads the saved accent from localStorage on mount', () => {
    localStorage.setItem('decnet_tweaks', JSON.stringify({ accent: 'violet' }));
    renderWithRouter(<AppearanceTab />);
    expect(screen.getByText('● VIOLET')).toBeInTheDocument();
  });

  it('switching to violet writes localStorage + the data-accent attribute', async () => {
    const user = userEvent.setup();
    renderWithRouter(<AppearanceTab />);
    await user.click(screen.getByText('○ VIOLET'));

    expect(screen.getByText('● VIOLET')).toBeInTheDocument();
    expect(document.documentElement.getAttribute('data-accent')).toBe('violet');
    const stored = JSON.parse(localStorage.getItem('decnet_tweaks') ?? '{}');
    expect(stored.accent).toBe('violet');
  });
});
