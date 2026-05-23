// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import PersonaCard from './PersonaCard';
import { BLANK } from './helpers';
import type { EmailPersona } from './types';

const persona: EmailPersona = {
  ...BLANK,
  name: 'Jane',
  email: 'jane@example.com',
  role: 'COO',
  tone: 'custom',
  tone_custom: 'wry but polite',
  mannerisms: ['uses bullets', 'signs Best,'],
  uses_llms_heavily: true,
};

describe('PersonaCard', () => {
  it('renders persona fields and fires edit/remove callbacks', () => {
    const onEdit = vi.fn();
    const onRemove = vi.fn();
    render(<PersonaCard persona={persona} onEdit={onEdit} onRemove={onRemove} />);
    expect(screen.getByText('Jane')).toBeInTheDocument();
    expect(screen.getByText('jane@example.com')).toBeInTheDocument();
    expect(screen.getByText('COO')).toBeInTheDocument();
    expect(screen.getByText('LLM-HEAVY')).toBeInTheDocument();
    expect(screen.getByText('wry but polite')).toBeInTheDocument();

    fireEvent.click(screen.getByTitle('Edit Jane'));
    fireEvent.click(screen.getByTitle('Remove Jane'));
    expect(onEdit).toHaveBeenCalledTimes(1);
    expect(onRemove).toHaveBeenCalledTimes(1);
  });

  it('shows em-dash-suppressed badge when not LLM-heavy and dash for empty mannerisms', () => {
    render(
      <PersonaCard
        persona={{ ...persona, uses_llms_heavily: false, mannerisms: [] }}
        onEdit={() => {}} onRemove={() => {}}
      />,
    );
    expect(screen.getByText('SUPPRESSED EM-DASH')).toBeInTheDocument();
    expect(screen.getByText('—')).toBeInTheDocument();
  });
});
