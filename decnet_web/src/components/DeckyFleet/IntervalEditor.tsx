// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from 'react';
import { RefreshCw } from '../../icons';
import Modal from '../Modal/Modal';

interface Props {
  open: boolean;
  deckyName: string;
  current: number | null;
  onClose: () => void;
  onSave: (minutes: number | null) => void;
}

/** Modal that toggles + slider-edits per-decky mutation intervals.
 *  Saves null when disabled, minutes otherwise. */
export const IntervalEditor: React.FC<Props> = ({
  open,
  deckyName,
  current,
  onClose,
  onSave,
}) => {
  const [enabled, setEnabled] = useState<boolean>(current !== null);
  const [minutes, setMinutes] = useState<number>(current ?? 30);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={`MUTATION INTERVAL · ${deckyName}`}
      icon={RefreshCw}
      accent="violet"
      footer={
        <>
          <button className="btn ghost" onClick={onClose}>CANCEL</button>
          <button className="btn violet" onClick={() => onSave(enabled ? minutes : null)}>SAVE</button>
        </>
      }
    >
      <div className="modal-body">
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', padding: 14, border: '1px solid var(--border)' }}>
          <input
            id="interval-enable"
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            style={{ accentColor: 'var(--matrix)' }}
          />
          <label htmlFor="interval-enable" style={{ fontSize: '0.8rem', letterSpacing: 1 }}>
            ENABLE PERIODIC MUTATION
          </label>
        </div>
        {enabled && (
          <div className="tweak-group">
            <label>INTERVAL ({minutes} minutes)</label>
            <input
              type="range"
              min={5}
              max={240}
              step={5}
              value={minutes}
              onChange={(e) => setMinutes(parseInt(e.target.value, 10))}
            />
            <div className="dim" style={{ fontSize: '0.65rem', letterSpacing: 1 }}>
              Applied on the next mutation cycle.
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
};
