// SPDX-License-Identifier: AGPL-3.0-or-later
import React from 'react';
import type { SortDir } from './types';

interface Props {
  col: string;
  activeCol: string;
  dir: SortDir;
  onSort: (col: string) => void;
  children: React.ReactNode;
}

const SortTh: React.FC<Props> = ({ col, activeCol, dir, onSort, children }) => (
  <th
    style={{ cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap' }}
    onClick={() => onSort(col)}
  >
    {children}
    {activeCol === col ? (dir === 'asc' ? ' ▲' : ' ▼') : ''}
  </th>
);

export default SortTh;
