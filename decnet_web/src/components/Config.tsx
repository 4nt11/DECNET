import React, { useEffect, useState } from 'react';
import {
  Settings, Users, Sliders, Shield, Palette, Activity,
} from '../icons';
import { useToast } from './Toasts/useToast';
import RuleStateControls from './RuleStateControls';
import './Dashboard.css';
import './Config.css';
import type { ConfigTab } from './Config/types';
import { useConfig } from './Config/useConfig';
import { WorkersPanel } from './Config/WorkersPanel';
import { LimitsTab } from './Config/tabs/LimitsTab';
import { UsersTab } from './Config/tabs/UsersTab';
import { GlobalsTab } from './Config/tabs/GlobalsTab';
import { AppearanceTab } from './Config/tabs/AppearanceTab';

const Config: React.FC = () => {
  const {
    config, loading, isAdmin,
    setDeploymentLimit, setGlobalMutationInterval,
    addUser, deleteUser, setUserRole, resetUserPassword,
    reinit,
  } = useConfig();
  const { push: pushToast } = useToast();

  const [activeTab, setActiveTab] = useState<ConfigTab>('limits');

  // If server didn't send users, force tab away from users.
  useEffect(() => {
    if (config && !config.users && activeTab === 'users') {
      setActiveTab('limits');
    }
  }, [config, activeTab]);

  if (loading) {
    return (
      <div className="logs-section">
        <div className="loader">LOADING CONFIGURATION...</div>
      </div>
    );
  }

  if (!config) {
    return (
      <div className="logs-section">
        <div style={{ padding: '40px', textAlign: 'center', opacity: 0.5 }}>
          <p>FAILED TO LOAD CONFIGURATION</p>
        </div>
      </div>
    );
  }

  const tabs: { key: ConfigTab; label: string; icon: React.ReactNode }[] = [
    { key: 'limits', label: 'DEPLOYMENT LIMITS', icon: <Sliders size={14} /> },
    ...(config.users
      ? [{ key: 'users' as const, label: 'USER MANAGEMENT', icon: <Users size={14} /> }]
      : []),
    { key: 'globals', label: 'GLOBAL VALUES', icon: <Settings size={14} /> },
    { key: 'appearance', label: 'APPEARANCE', icon: <Palette size={14} /> },
    ...(isAdmin
      ? [{ key: 'workers' as const, label: 'WORKERS', icon: <Activity size={14} /> }]
      : []),
    ...(isAdmin
      ? [{ key: 'ttp' as const, label: 'TTP RULES', icon: <Shield size={14} /> }]
      : []),
  ];

  return (
    <div className="config-page">
      <div className="logs-section">
        <div className="section-header">
          <Shield size={20} />
          <h2>SYSTEM CONFIGURATION</h2>
        </div>
      </div>

      <div className="config-tabs">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            className={`config-tab ${activeTab === tab.key ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.key)}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'limits' && (
        <LimitsTab
          isAdmin={isAdmin}
          initialValue={config.deployment_limit}
          onSave={setDeploymentLimit}
        />
      )}

      {activeTab === 'users' && config.users && (
        <UsersTab
          users={config.users}
          onDeleteUser={deleteUser}
          onSetUserRole={setUserRole}
          onResetUserPassword={resetUserPassword}
          onAddUser={addUser}
        />
      )}

      {activeTab === 'globals' && (
        <GlobalsTab
          isAdmin={isAdmin}
          developerMode={config.developer_mode === true}
          initialInterval={config.global_mutation_interval}
          onSaveInterval={setGlobalMutationInterval}
          onReinit={reinit}
        />
      )}

      {activeTab === 'appearance' && <AppearanceTab />}

      {activeTab === 'workers' && isAdmin && (
        <WorkersPanel pushToast={pushToast} />
      )}

      {/* RuleStateControls also self-gates on /config?.role so a state
          leak can't render it. */}
      {activeTab === 'ttp' && isAdmin && <RuleStateControls />}
    </div>
  );
};

export default Config;
