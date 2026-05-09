import type { ReactElement, ReactNode } from 'react';
import { render, type RenderOptions, type RenderResult } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { ToastProvider } from '../components/Toasts/ToastProvider';

export interface RenderWithRouterOptions extends Omit<RenderOptions, 'wrapper'> {
  /** Initial URL the MemoryRouter starts at. */
  initialEntries?: string[];
  /** When set, the rendered UI is mounted at this route path so `useParams` resolves. */
  path?: string;
}

const Wrap = ({ children }: { children: ReactNode }) => (
  <ToastProvider>{children}</ToastProvider>
);

export const renderWithRouter = (
  ui: ReactElement,
  { initialEntries = ['/'], path, ...rest }: RenderWithRouterOptions = {},
): RenderResult => {
  const tree = path ? (
    <Routes>
      <Route path={path} element={ui} />
    </Routes>
  ) : (
    ui
  );
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <Wrap>{tree}</Wrap>
    </MemoryRouter>,
    rest,
  );
};
