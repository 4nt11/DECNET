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
});
