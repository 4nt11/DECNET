import React from 'react';
import { Keyboard } from 'lucide-react';
import Modal from '../Modal/Modal';
import './ShortcutsHelp.css';

interface Props {
  open: boolean;
  onClose: () => void;
}

interface Binding {
  keys: string;
  label: string;
}

const GLOBAL: Binding[] = [
  { keys: 'Alt+K', label: 'Open command palette' },
  { keys: '?', label: 'Show this cheatsheet' },
  { keys: '/', label: 'Focus page search' },
  { keys: 'Esc', label: 'Close modal / palette' },
];

const NAV: Binding[] = [
  { keys: 'G D', label: 'Dashboard' },
  { keys: 'G F', label: 'Decoy Fleet' },
  { keys: 'G M', label: 'MazeNET' },
  { keys: 'G L', label: 'Live Logs' },
  { keys: 'G B', label: 'Bounty Vault' },
  { keys: 'G A', label: 'Attackers' },
  { keys: 'G S', label: 'SWARM Hosts' },
  { keys: 'G U', label: 'Remote Updates' },
  { keys: 'G E', label: 'Agent Enrollment' },
  { keys: 'G C', label: 'Config' },
];

const PALETTE: Binding[] = [
  { keys: '↑ ↓', label: 'Navigate entries' },
  { keys: '⏎', label: 'Run selected entry' },
  { keys: 'Esc', label: 'Dismiss palette' },
];

const Group: React.FC<{ title: string; rows: Binding[] }> = ({ title, rows }) => (
  <section className="shk-group">
    <h4 className="shk-title">{title}</h4>
    <div className="shk-rows">
      {rows.map(r => (
        <div className="shk-row" key={r.keys}>
          <span className="shk-keys">
            {r.keys.split(' ').map((k, i) => (
              <kbd key={i}>{k}</kbd>
            ))}
          </span>
          <span className="shk-label">{r.label}</span>
        </div>
      ))}
    </div>
  </section>
);

const ShortcutsHelp: React.FC<Props> = ({ open, onClose }) => (
  <Modal
    open={open}
    onClose={onClose}
    title="KEYBOARD SHORTCUTS"
    icon={Keyboard}
    accent="violet"
    width="wide"
  >
    <div className="modal-body shk-body">
      <Group title="GLOBAL" rows={GLOBAL} />
      <Group title="NAVIGATION (G-CHORD)" rows={NAV} />
      <Group title="COMMAND PALETTE" rows={PALETTE} />
    </div>
  </Modal>
);

export default ShortcutsHelp;
