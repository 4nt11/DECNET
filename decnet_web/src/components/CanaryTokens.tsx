import React, { useEffect, useState } from 'react';
import { Plus, Upload, Target } from '../icons';
import CanaryTokenDrawer from './CanaryTokenDrawer';
import type { CanaryTokenRow } from './CanaryTokenDrawer';
import { STATE_COLOR } from './CanaryTokens/types';
import { Stat } from './CanaryTokens/ui';
import { extractError } from './CanaryTokens/helpers';
import { useCanaryTokens } from './CanaryTokens/useCanaryTokens';
import { CreateTokenModal } from './CanaryTokens/CreateTokenModal';
import { UploadModal } from './CanaryTokens/UploadModal';
import {
  FileDropModal, loadFileDrops, saveFileDrops,
  type FileDropEntry,
} from './CanaryTokens/FileDropModal';
import {
  TokenListView,
  type StateFilter, type ScopeFilter,
} from './CanaryTokens/TokenListView';
import { BlobListView } from './CanaryTokens/BlobListView';
import { FileDropListView } from './CanaryTokens/FileDropListView';

type Tab = 'tokens' | 'blobs' | 'filedrops';

const CanaryTokens: React.FC = () => {
  const {
    tokens, blobs, deckies, topologies, loading, error,
    prependToken, prependBlob, markTokenRevoked, deleteBlob,
  } = useCanaryTokens();

  // Pure-UI state. The local fileDrops log lives entirely in the
  // browser; the server doesn't persist it.
  const [tab, setTab] = useState<Tab>('tokens');
  const [fileDrops, setFileDrops] = useState<FileDropEntry[]>(() => loadFileDrops());
  const [filter, setFilter] = useState('');
  const [stateFilter, setStateFilter] = useState<StateFilter>('all');
  const [scopeFilter, setScopeFilter] = useState<ScopeFilter>('all');
  const [showCreate, setShowCreate] = useState(false);
  const [showUpload, setShowUpload] = useState(false);
  const [showFileDrop, setShowFileDrop] = useState(false);
  const [drawerToken, setDrawerToken] = useState<CanaryTokenRow | null>(null);

  // Alt+C / Alt+D — open create-token / drop-file modals
  // (per feedback_linux_meta_key — never Meta/⌘ on Linux).
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const anyModalOpen = showCreate || showUpload || showFileDrop || drawerToken;
      if (anyModalOpen) return;
      if (e.altKey && e.key.toLowerCase() === 'c') {
        e.preventDefault();
        setShowCreate(true);
      } else if (e.altKey && e.key.toLowerCase() === 'd') {
        e.preventDefault();
        setShowFileDrop(true);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [showCreate, showUpload, showFileDrop, drawerToken]);

  const counts = (() => {
    const c = { planted: 0, revoked: 0, failed: 0, hits: 0 };
    for (const t of tokens) {
      c[t.state] += 1;
      c.hits += t.trigger_count;
    }
    return c;
  })();

  const handleDeleteBlob = async (uuid: string) => {
    if (!window.confirm('Delete this blob? Refused if any token still references it.')) return;
    const r = await deleteBlob(uuid);
    if (!r.ok) alert(extractError(r.reason, 'Delete failed.'));
  };

  const handleClearFileDrops = () => {
    if (!window.confirm('Clear local file drop history? This does not delete dropped files.')) return;
    setFileDrops([]);
    saveFileDrops([]);
  };

  return (
    <div className="fleet-root canary-tokens-root" style={{ padding: '24px', color: 'var(--text-color)' }}>
      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Target size={22} className="violet-accent" />
            <h1>CANARY TOKENS</h1>
          </div>
          <span className="page-sub">
            {tokens.length} TOKEN{tokens.length === 1 ? '' : 'S'} · {counts.planted} PLANTED · {counts.hits} TOTAL HIT{counts.hits === 1 ? '' : 'S'} · {blobs.length} UPLOADED BLOB{blobs.length === 1 ? '' : 'S'}
          </span>
        </div>
        <div className="actions">
          <button className="btn" onClick={() => setShowUpload(true)}>
            <Upload size={12} /> UPLOAD ARTIFACT
          </button>
          <button className="btn" onClick={() => setShowFileDrop(true)} title="Alt+D">
            <Upload size={12} /> DROP FILE
          </button>
          <button className="btn violet" onClick={() => setShowCreate(true)} title="Alt+C">
            <Plus size={12} /> NEW TOKEN
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '12px', marginBottom: '24px', flexWrap: 'wrap' }}>
        <Stat label="PLANTED" value={counts.planted} color={STATE_COLOR.planted} />
        <Stat label="REVOKED" value={counts.revoked} color={STATE_COLOR.revoked} />
        <Stat label="FAILED" value={counts.failed} color={STATE_COLOR.failed} />
        <Stat label="TOTAL HITS" value={counts.hits} color="#00ff88" />
        <Stat label="UPLOADED BLOBS" value={blobs.length} color="var(--text-color)" />
      </div>

      <div style={{ display: 'flex', gap: '8px', marginBottom: '12px', borderBottom: '1px solid var(--border-color, #30363d)' }}>
        {(['tokens', 'blobs', 'filedrops'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              background: 'transparent', border: 'none',
              color: tab === t ? 'var(--text-color)' : 'var(--dim-color)',
              padding: '8px 16px', cursor: 'pointer',
              borderBottom: tab === t ? '2px solid var(--accent-color, #00ff88)' : '2px solid transparent',
              fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '0.05em',
            }}
          >
            {t === 'tokens'
              ? `Tokens (${tokens.length})`
              : t === 'blobs'
                ? `Blobs (${blobs.length})`
                : `File drops (${fileDrops.length})`}
          </button>
        ))}
      </div>

      {tab === 'tokens' && (
        <TokenListView
          tokens={tokens}
          loading={loading}
          error={error}
          filter={filter}
          setFilter={setFilter}
          stateFilter={stateFilter}
          setStateFilter={setStateFilter}
          scopeFilter={scopeFilter}
          setScopeFilter={setScopeFilter}
          onPick={setDrawerToken}
        />
      )}

      {tab === 'blobs' && (
        <BlobListView blobs={blobs} onDelete={handleDeleteBlob} />
      )}

      {tab === 'filedrops' && (
        <FileDropListView fileDrops={fileDrops} onClear={handleClearFileDrops} />
      )}

      {showCreate && (
        <CreateTokenModal
          blobs={blobs}
          deckies={deckies}
          topologies={topologies}
          onClose={() => setShowCreate(false)}
          onCreated={(t) => {
            prependToken(t);
            setShowCreate(false);
          }}
        />
      )}
      {showUpload && (
        <UploadModal
          onClose={() => setShowUpload(false)}
          onUploaded={(b) => {
            prependBlob(b);
            setShowUpload(false);
          }}
        />
      )}
      {drawerToken && (
        <CanaryTokenDrawer
          token={drawerToken}
          onClose={() => setDrawerToken(null)}
          onRevoked={(uuid) => {
            markTokenRevoked(uuid);
            setDrawerToken(null);
          }}
        />
      )}
      {showFileDrop && (
        <FileDropModal
          deckies={deckies}
          topologies={topologies}
          onClose={() => setShowFileDrop(false)}
          onDropped={(entry) => {
            setFileDrops((prev) => {
              const next = [entry, ...prev].slice(0, 200);
              saveFileDrops(next);
              return next;
            });
            setShowFileDrop(false);
            setTab('filedrops');
          }}
        />
      )}
    </div>
  );
};

export default CanaryTokens;
