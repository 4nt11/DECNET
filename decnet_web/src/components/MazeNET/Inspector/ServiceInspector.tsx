// SPDX-License-Identifier: AGPL-3.0-or-later
import React from 'react';
import { Shield, Trash2 } from '../../../icons';
import ServiceConfigForm from '../../ServiceConfigForm';
import { DEFAULT_SERVICES } from '../data';
import type { MazeNode, Net } from '../types';

interface Props {
  /** The selected service entry. The id is the service slug; nodeId
   *  identifies the parent decky in the topology. */
  serviceSel: { type: 'service'; id: string; nodeId: string };
  nodes: MazeNode[];
  nets: Net[];
  topologyId?: string;
  topologyStatus?: string;
  onRemoveService?: (nodeId: string, slug: string) => void;
}

const ServiceInspector: React.FC<Props> = ({
  serviceSel, nodes, nets, topologyId, topologyStatus, onRemoveService,
}) => {
  const serviceMeta = DEFAULT_SERVICES.find((s) => s.slug === serviceSel.id);
  const serviceParent = nodes.find((n) => n.id === serviceSel.nodeId);
  const serviceParentNet = serviceParent
    ? nets.find((n) => n.id === serviceParent.netId)
    : undefined;

  return (
    <>
      <div className="inspector-head">
        <Shield
          size={14}
          className={serviceMeta?.risk === 'high' ? 'alert-text' : 'violet-accent'}
        />
        <span className="inspector-head-title">
          {serviceMeta?.name ?? serviceSel.id.toUpperCase()}
        </span>
        {serviceMeta && (
          <span className={`chip inspector-head-chip ${
            serviceMeta.risk === 'high' ? 'alert'
            : serviceMeta.risk === 'med' ? 'violet'
            : 'dim-chip'
          }`}>
            {serviceMeta.risk.toUpperCase()}
          </span>
        )}
      </div>
      <div className="kvs">
        <div className="k">EXPOSED ON</div>
        <div className="v violet-accent">{serviceParent?.name ?? '—'}</div>
        <div className="k">PROTOCOL</div>
        <div className="v">{(serviceMeta?.proto ?? '—').toUpperCase()}</div>
        <div className="k">PORT</div>
        <div className="v" style={{ fontWeight: 700 }}>{serviceMeta?.port ?? '—'}</div>
        <div className="k">SUBNET</div>
        <div className="v">{serviceParentNet?.label ?? '—'}</div>
      </div>
      {topologyId && serviceParent && serviceParent.kind !== 'observed' && (
        <ServiceConfigForm
          key={`${serviceParent.name}:${serviceSel.id}`}
          deckyName={serviceParent.name}
          serviceSlug={serviceSel.id}
          topologyId={topologyId}
          currentConfig={
            ((serviceParent.decky_config as { service_config?: Record<string, Record<string, unknown>> } | undefined)
              ?.service_config?.[serviceSel.id]) ?? {}
          }
        />
      )}
      {onRemoveService && serviceParent && serviceParent.kind !== 'observed' && (
        <button
          type="button"
          className="maze-btn alert small"
          disabled={topologyStatus === 'degraded'}
          title={topologyStatus === 'degraded' ? 'topology degraded — mutations blocked' : undefined}
          onClick={() => onRemoveService(serviceSel.nodeId, serviceSel.id)}
        >
          <Trash2 size={10} /> REMOVE SERVICE
        </button>
      )}
    </>
  );
};

export default ServiceInspector;
