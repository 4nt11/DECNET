// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import ThemeLab from '../ThemeLab';

describe('ThemeLab', () => {
  it('renders the page header stub', () => {
    render(<ThemeLab />);
    expect(screen.getByTestId('theme-lab')).toBeInTheDocument();
    expect(screen.getByText(/THEME LAB/i)).toBeInTheDocument();
    expect(screen.getByText(/dev only/i)).toBeInTheDocument();
  });

  it('renders every primitive section', () => {
    render(<ThemeLab />);
    for (const id of [
      'swatches',
      'type',
      'buttons',
      'badges',
      'banners',
      'metrics',
      'table',
      'inputs',
      'drawer',
      'netbox',
    ]) {
      expect(screen.getByTestId(`lab-section-${id}`)).toBeInTheDocument();
    }
  });

  it('renders button variants × states', () => {
    render(<ThemeLab />);
    // 5 variants × 3 states (normal/hover/disabled) = 15 rendered buttons
    // plus the drawer's CLOSE button = 16 total.
    const allButtons = screen.getAllByRole('button');
    expect(allButtons.length).toBeGreaterThanOrEqual(15);
    // Disabled buttons exist
    const disabled = allButtons.filter((b) => (b as HTMLButtonElement).disabled);
    expect(disabled.length).toBe(5);
  });

  it('renders the four net-box compose states', () => {
    render(<ThemeLab />);
    for (const s of ['INTERNET', 'INACTIVE', 'SELECTED', 'DROP-TARGET']) {
      expect(screen.getByText(s)).toBeInTheDocument();
    }
  });
});
