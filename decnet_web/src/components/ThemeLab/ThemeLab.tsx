import React, { useEffect, useState } from 'react';
import ThemeToggle from './ThemeToggle';
import './ThemeLab.css';

/* Kitchen-sink theme lab.
 *
 * Renders every primitive in the design system so theme-token edits
 * can be evaluated against all states at once. Dev-only (gated in
 * App.tsx via isDeveloperMode()).
 *
 * Conventions:
 *  - Wrapper uses .fleet-root so global .btn/.btn.violet/etc resolve
 *    the same way they do on real pages.
 *  - All colours come from index.css tokens. Lab-local CSS only owns
 *    layout (grid for swatches, section spacing).
 *  - Every section has a data-testid for smoke-test assertions. */

// Tokens enumerated explicitly so the lab serves as documentation
// of the supported design system surface, not a runtime introspection.
const COLOR_TOKENS: ReadonlyArray<readonly [string, string]> = [
  ['--bg', 'background'],
  ['--matrix', 'primary text / live'],
  ['--violet', 'accent'],
  ['--panel', 'panel surface'],
  ['--border', 'borders'],
  ['--alert', 'alert / critical'],
  ['--accent', 'active accent (matrix or violet)'],
  ['--accent-tint-10', 'accent surface tint'],
  ['--matrix-tint-5', 'subtle matrix wash'],
  ['--matrix-tint-10', 'matrix tint'],
  ['--matrix-tint-30', 'matrix tint strong'],
  ['--violet-tint-10', 'violet tint'],
  ['--alert-tint-10', 'alert tint'],
  ['--grid-line', 'scangrid line'],
];

const TYPE_SCALE: ReadonlyArray<readonly [string, string]> = [
  ['--fs-display', 'DISPLAY'],
  ['--fs-hero', 'HERO'],
  ['--fs-page', 'PAGE'],
  ['--fs-head', 'HEAD'],
  ['--fs-base', 'BASE'],
  ['--fs-ui', 'UI'],
  ['--fs-body', 'BODY'],
  ['--fs-small', 'SMALL'],
  ['--fs-tiny', 'TINY'],
  ['--fs-mini', 'MINI'],
  ['--fs-micro', 'MICRO'],
];

/* WCAG relative luminance + contrast ratio.
 * Accepts any css color string by going through the canvas trick. */
function parseColor(input: string): [number, number, number, number] | null {
  if (typeof document === 'undefined') return null;
  let ctx: CanvasRenderingContext2D | null = null;
  try {
    ctx = document.createElement('canvas').getContext('2d');
  } catch {
    return null;
  }
  if (!ctx) return null;
  ctx.fillStyle = '#000';
  ctx.fillStyle = input;
  const computed = ctx.fillStyle as string;
  // computed is now either #rrggbb or rgba(...)
  if (computed.startsWith('#')) {
    const r = parseInt(computed.slice(1, 3), 16);
    const g = parseInt(computed.slice(3, 5), 16);
    const b = parseInt(computed.slice(5, 7), 16);
    return [r, g, b, 1];
  }
  const m = computed.match(/rgba?\(([^)]+)\)/);
  if (!m) return null;
  const parts = m[1].split(',').map((s) => parseFloat(s.trim()));
  return [parts[0], parts[1], parts[2], parts[3] ?? 1];
}

function relLum(r: number, g: number, b: number): number {
  const ch = (c: number) => {
    const n = c / 255;
    return n <= 0.03928 ? n / 12.92 : Math.pow((n + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b);
}

function contrast(fg: string, bg: string): number | null {
  const a = parseColor(fg);
  const b = parseColor(bg);
  if (!a || !b) return null;
  const la = relLum(a[0], a[1], a[2]);
  const lb = relLum(b[0], b[1], b[2]);
  const [hi, lo] = la > lb ? [la, lb] : [lb, la];
  return (hi + 0.05) / (lo + 0.05);
}

interface Resolved {
  name: string;
  desc: string;
  value: string;
  vsBg: number | null;
}

function useResolvedTokens(deps: unknown[] = []): Resolved[] {
  const [rows, setRows] = useState<Resolved[]>([]);
  useEffect(() => {
    const cs = getComputedStyle(document.documentElement);
    const bg = cs.getPropertyValue('--bg').trim() || '#000';
    setRows(
      COLOR_TOKENS.map(([name, desc]) => {
        const value = cs.getPropertyValue(name).trim() || '—';
        const vsBg = name === '--bg' ? null : contrast(value, bg);
        return { name, desc, value, vsBg };
      }),
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return rows;
}

const Section: React.FC<{
  id: string;
  title: string;
  children: React.ReactNode;
}> = ({ id, title, children }) => (
  <section className="lab-section" data-testid={`lab-section-${id}`}>
    <h2 className="lab-section-title">{title}</h2>
    <div className="lab-section-body">{children}</div>
  </section>
);

const ColorSwatches: React.FC = () => {
  const rows = useResolvedTokens();
  return (
    <div className="lab-swatch-grid">
      {rows.map((r) => (
        <div className="lab-swatch" key={r.name}>
          <div
            className="lab-swatch-chip"
            style={{ background: `var(${r.name})` }}
          />
          <div className="lab-swatch-meta">
            <code>{r.name}</code>
            <span className="lab-swatch-value">{r.value}</span>
            <span className="lab-swatch-desc">{r.desc}</span>
            {r.vsBg !== null && (
              <span
                className={`lab-swatch-contrast ${
                  r.vsBg >= 4.5 ? 'ok' : r.vsBg >= 3 ? 'warn' : 'fail'
                }`}
              >
                {r.vsBg.toFixed(2)}:1
              </span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
};

const TypeScale: React.FC = () => (
  <div className="lab-type-list">
    {TYPE_SCALE.map(([token, label]) => (
      <div className="lab-type-row" key={token}>
        <code className="lab-type-token">{token}</code>
        <div
          className="lab-type-sample"
          style={{ fontSize: `var(${token})`, letterSpacing: 'var(--ls-title)' }}
        >
          {label} · DECNET
        </div>
      </div>
    ))}
  </div>
);

const Buttons: React.FC = () => (
  <div className="lab-btn-grid">
    {(
      [
        ['default', ''],
        ['violet', 'violet'],
        ['alert', 'alert'],
        ['ghost', 'ghost'],
        ['small', 'small'],
      ] as const
    ).map(([label, mod]) => (
      <div className="lab-btn-row" key={label}>
        <span className="lab-btn-label">{label}</span>
        <button className={`btn ${mod}`}>NORMAL</button>
        <button className={`btn ${mod}`} data-state="hover-demo">
          HOVER
        </button>
        <button className={`btn ${mod}`} disabled>
          DISABLED
        </button>
      </div>
    ))}
  </div>
);

const Badges: React.FC = () => (
  <div className="lab-badge-row">
    <span className="lab-pill live">● LIVE</span>
    <span className="lab-pill inactive">○ INACTIVE</span>
    <span className="lab-pill threat">▲ THREAT: ELEVATED</span>
    <span className="nav-badge">7</span>
    <span className="nav-badge">99+</span>
  </div>
);

const Banners: React.FC = () => (
  <div className="lab-banner-stack">
    <div className="info-banner">
      <em>HEADS UP.</em> Tokens drive every surface — edits to{' '}
      <code>index.css</code> reflow the entire app at once.
    </div>
    <div className="info-banner lab-banner-error">
      <em>ERROR.</em> Failed to resolve <code>--accent</code> — check the
      cascade.
    </div>
  </div>
);

const MetricCards: React.FC = () => (
  <div className="lab-metric-grid">
    <div className="lab-stat-card">
      <div className="lab-stat-label">TOTAL ATTEMPTS</div>
      <div className="lab-stat-value">63,678</div>
      <div className="lab-stat-foot">+0 in last 5m</div>
    </div>
    <div className="lab-stat-card empty">
      <div className="lab-stat-label">QUEUED PROBES</div>
      <div className="lab-stat-value lab-stat-empty">—</div>
      <div className="lab-stat-foot dim">no data yet</div>
    </div>
  </div>
);

const TableRows: React.FC = () => (
  <table className="lab-table">
    <thead>
      <tr>
        <th>SOURCE</th>
        <th>TARGET</th>
        <th>STATE</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>10.0.0.41</td>
        <td>decoy-7</td>
        <td className="ok">ACTIVE</td>
      </tr>
      <tr className="hover-demo">
        <td>10.0.0.42</td>
        <td>decoy-3</td>
        <td className="ok">ACTIVE</td>
      </tr>
      <tr className="selected">
        <td>10.0.0.43</td>
        <td>decoy-9</td>
        <td className="warn">PROBING</td>
      </tr>
      <tr className="drop-target">
        <td>10.0.0.44</td>
        <td>(drop here)</td>
        <td className="dim">—</td>
      </tr>
    </tbody>
  </table>
);

const Inputs: React.FC = () => (
  <div className="lab-input-grid">
    <input type="text" placeholder="text input" defaultValue="" />
    <input type="search" placeholder="search…" />
    <select defaultValue="b">
      <option value="a">option a</option>
      <option value="b">option b</option>
    </select>
    <label className="lab-checkbox">
      <input type="checkbox" defaultChecked /> enabled flag
    </label>
  </div>
);

const Drawer: React.FC = () => (
  <aside className="lab-drawer">
    <header className="lab-drawer-head">
      <span>DRAWER · SAMPLE</span>
      <button className="btn ghost small" type="button">
        CLOSE
      </button>
    </header>
    <div className="lab-drawer-body">
      <p>
        Standalone panel preview. Real drawers portal into the layout root;
        this one sits inline so token impact is visible.
      </p>
    </div>
  </aside>
);

const NetBoxes: React.FC = () => (
  <div className="lab-netbox-grid">
    {(['internet', 'inactive', 'selected', 'drop-target'] as const).map((s) => (
      <div className={`lab-netbox ${s}`} key={s}>
        <span className="lab-netbox-label">{s.toUpperCase()}</span>
      </div>
    ))}
  </div>
);

const ThemeLab: React.FC = () => {
  return (
    <div className="fleet-root theme-lab" data-testid="theme-lab">
      <header className="page-header lab-page-header">
        <div className="page-title-group">
          <h1>THEME LAB</h1>
          <span className="page-sub">
            dev only · primitive zoo for theme regression
          </span>
        </div>
        <ThemeToggle />
      </header>

      <Section id="swatches" title="COLOUR TOKENS">
        <ColorSwatches />
      </Section>
      <Section id="type" title="TYPOGRAPHY SCALE">
        <TypeScale />
      </Section>
      <Section id="buttons" title="BUTTONS">
        <Buttons />
      </Section>
      <Section id="badges" title="BADGES & STATUS PILLS">
        <Badges />
      </Section>
      <Section id="banners" title="BANNERS">
        <Banners />
      </Section>
      <Section id="metrics" title="METRIC CARDS">
        <MetricCards />
      </Section>
      <Section id="table" title="TABLE ROWS">
        <TableRows />
      </Section>
      <Section id="inputs" title="FORM INPUTS">
        <Inputs />
      </Section>
      <Section id="drawer" title="DRAWER / MODAL">
        <Drawer />
      </Section>
      <Section id="netbox" title="NET-BOX STATES">
        <NetBoxes />
      </Section>
    </div>
  );
};

export default ThemeLab;
