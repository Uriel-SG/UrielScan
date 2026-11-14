import React, { useState } from 'react';
import { 
  Clock, 
  Calendar, 
  Play, 
  Plus, 
  Trash2, 
  Power, 
  CheckCircle2, 
  Building2, 
  Globe, 
  Layers,
  Loader2 
} from 'lucide-react';
import { Schedule, Organization } from '../types';
import { api } from '../services/api';
import { useToast, ConfirmModal } from './UIFeedback';
import { useI18n } from '../i18n/LanguageContext';

interface SchedulerViewProps {
  schedules: Schedule[];
  organizations: Organization[];
  selectedOrgId: string;
  onRefreshSchedules: () => void;
  onScanLaunched: (scanId: string) => void;
}

export const SchedulerView: React.FC<SchedulerViewProps> = ({
  schedules,
  organizations,
  selectedOrgId,
  onRefreshSchedules,
  onScanLaunched,
}) => {
  const { lang, locale, L } = useI18n();
  const { showToast } = useToast();
  const [isCreating, setIsCreating] = useState<boolean>(false);
  const initialOrg = organizations.find((o) => o.id === (selectedOrgId !== 'ALL' ? selectedOrgId : organizations[0]?.id)) || organizations[0];
  const [name, setName] = useState<string>(() => (lang === 'it' ? 'Scansione Periodica' : 'Periodic Scan'));
  const [orgId, setOrgId] = useState<string>(initialOrg?.id || '1');
  const [targets, setTargets] = useState<string>(initialOrg?.target_scope || '192.168.1.0/24');
  const [profile, setProfile] = useState<string>('Full Purple Assessment (Rete + Web)');
  const [frequency, setFrequency] = useState<'hourly' | 'daily' | 'weekly' | 'monthly' | 'cron'>('daily');
  const [timeOfDay, setTimeOfDay] = useState<string>('02:30');
  const [cronExpr, setCronExpr] = useState<string>('0 2 * * *');

  const selectedOrg = organizations.find((o) => o.id === orgId) || organizations[0];
  const orgNetworks = (selectedOrg?.target_scope || '')
    .split(/[,;\n]+/)
    .map((s) => s.trim())
    .filter(Boolean);

  // Confirm delete modal state
  const [deleteTargetId, setDeleteTargetId] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState<boolean>(false);

  const filteredSchedules = selectedOrgId === 'ALL'
    ? schedules
    : schedules.filter((s) => s.org_id === selectedOrgId);

  const handleToggleEnable = async (schedule: Schedule) => {
    try {
      await api.updateSchedule(schedule.id, { enabled: !schedule.enabled });
      showToast(
        L(
          `Schedule ${!schedule.enabled ? 'enabled' : 'disabled'}.`,
          `Pianificazione ${!schedule.enabled ? 'attivata' : 'disattivata'}.`
        ),
        'info'
      );
      onRefreshSchedules();
    } catch (err: any) {
      showToast(err.message || L('Error updating schedule.', 'Errore aggiornamento schedulazione.'), 'error');
    }
  };

  const confirmDeleteSchedule = async () => {
    if (!deleteTargetId) return;
    setIsDeleting(true);
    try {
      await api.deleteSchedule(deleteTargetId);
      showToast(L('Schedule deleted.', 'Schedulazione eliminata.'), 'info');
      setDeleteTargetId(null);
      onRefreshSchedules();
    } catch (err: any) {
      showToast(err.message || L('Error deleting schedule.', 'Errore eliminazione schedulazione.'), 'error');
    } finally {
      setIsDeleting(false);
    }
  };

  const handleRunNow = async (id: string) => {
    try {
      const res = await api.runScheduleNow(id);
      if (res.success) {
        showToast(
          L(`Scan #${res.scan_id} started from schedule.`, `Scansione #${res.scan_id} avviata dalla schedulazione.`),
          'success',
          L('Scan Launched', 'Scansione Avviata')
        );
        onScanLaunched(res.scan_id);
      }
    } catch (err: any) {
      showToast(err.message || L('Error launching scan.', 'Errore avvio scansione.'), 'error');
    }
  };

  const handleCreateSchedule = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createSchedule({
        org_id: orgId,
        name,
        targets,
        profile,
        frequency,
        time_of_day: timeOfDay,
        cron_expr: frequency === 'cron' ? cronExpr : undefined,
        enabled: true,
      });
      setIsCreating(false);
      showToast(L('New schedule saved.', 'Nuova schedulazione salvata.'), 'success');
      onRefreshSchedules();
    } catch (err: any) {
      showToast(err.message || L('Error creating schedule.', 'Errore creazione pianificazione.'), 'error');
    }
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="card-industrial p-4 flex flex-col md:flex-row md:items-center justify-between gap-2">
        <div>
          <div className="flex items-center space-x-2 text-[11px] uppercase font-bold tracking-wider text-theme-accent">
            <Clock className="w-3.5 h-3.5" />
            <span>{L('Automation & Background Scheduler', 'Automazione & Scheduler Background')}</span>
          </div>
          <h1 className="text-base font-bold text-theme-primary mt-0.5 tracking-tight">
            {L('Scheduled Periodic Scans', 'Pianificazione Scansioni Periodiche')}
          </h1>
          <p className="text-xs text-theme-secondary mt-0.5">
            {L(
              'Scheduled execution with cron and hourly intervals for continuous security posture monitoring.',
              'Esecuzione programmata con cron e intervalli orari per monitoraggio continuo della postura di sicurezza.'
            )}
          </p>
        </div>

        <button
          onClick={() => setIsCreating(!isCreating)}
          className="btn-primary flex items-center space-x-1.5 px-3.5 py-1.5 text-xs font-semibold self-start md:self-auto"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>{isCreating ? L('Cancel', 'Annulla') : L('New Schedule', 'Nuova Pianificazione')}</span>
        </button>
      </div>

      {/* Creation form */}
      {isCreating && (
        <form onSubmit={handleCreateSchedule} className="card-industrial p-4 space-y-3">
          <h2 className="text-xs font-bold text-theme-primary flex items-center space-x-2">
            <Plus className="w-3.5 h-3.5 text-theme-accent" />
            <span>{L('New Scheduling Rule', 'Nuova Regola di Schedulazione')}</span>
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-medium text-theme-secondary mb-1">
                {L('Organization', 'Organizzazione')}
              </label>
              <select
                value={orgId}
                onChange={(e) => {
                  setOrgId(e.target.value);
                  const nextOrg = organizations.find((o) => o.id === e.target.value);
                  if (nextOrg?.target_scope) setTargets(nextOrg.target_scope);
                }}
                className="input-industrial w-full px-2.5 py-1.5 text-xs"
              >
                {organizations.map((org) => (
                  <option key={org.id} value={org.id} className="bg-panel text-theme-primary">
                    {org.name}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-theme-secondary mb-1">
                {L('Schedule Name', 'Nome Pianificazione')}
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="input-industrial w-full px-2.5 py-1.5 text-xs"
                required
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-theme-secondary mb-1">
                {L(`Registered Network (${selectedOrg?.name || 'Company'}) / Target Scope`, `Rete Registrata (${selectedOrg?.name || 'Azienda'}) / Target Scope`)}
              </label>
              <div className="flex flex-col space-y-1.5">
                {orgNetworks.length > 0 && (
                  <select
                    value={orgNetworks.includes(targets.trim()) ? targets.trim() : '__custom__'}
                    onChange={(e) => {
                      if (e.target.value !== '__custom__') setTargets(e.target.value);
                    }}
                    className="input-industrial w-full px-2.5 py-1 text-xs font-mono"
                  >
                    {orgNetworks.map((net) => (
                      <option key={net} value={net} className="bg-panel text-theme-primary">
                        {L('Registered Network', 'Rete Registrata')}: {net}
                      </option>
                    ))}
                    <option value="__custom__" className="bg-panel text-theme-accent">
                      {L('Manual input...', 'Inserimento manuale...')}
                    </option>
                  </select>
                )}
                <input
                  type="text"
                  value={targets}
                  onChange={(e) => setTargets(e.target.value)}
                  placeholder={L('e.g. 192.168.1.0/24 or manual IP', 'es. 192.168.1.0/24 o IP manuale')}
                  className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-theme-secondary mb-1">
                {L('Frequency', 'Frequenza')}
              </label>
              <select
                value={frequency}
                onChange={(e) => setFrequency(e.target.value as any)}
                className="input-industrial w-full px-2.5 py-1.5 text-xs"
              >
                <option value="hourly" className="bg-panel text-theme-primary">{L('Hourly', 'Ogni Ora')}</option>
                <option value="daily" className="bg-panel text-theme-primary">{L('Daily', 'Giornaliera')}</option>
                <option value="weekly" className="bg-panel text-theme-primary">{L('Weekly', 'Settimanale')}</option>
                <option value="monthly" className="bg-panel text-theme-primary">{L('Monthly', 'Mensile')}</option>
                <option value="cron" className="bg-panel text-theme-primary">{L('Cron Expression', 'Espressione Cron')}</option>
              </select>
            </div>

            {frequency !== 'cron' && (
              <div>
                <label className="block text-xs font-medium text-theme-secondary mb-1">
                  {L('Execution Time', 'Orario Esecuzione')}
                </label>
                <input
                  type="time"
                  value={timeOfDay}
                  onChange={(e) => setTimeOfDay(e.target.value)}
                  className="input-industrial w-full px-2.5 py-1.5 text-xs"
                />
              </div>
            )}

            {frequency === 'cron' && (
              <div>
                <label className="block text-xs font-medium text-theme-secondary mb-1">
                  {L('Cron Expression', 'Cron Expression')}
                </label>
                <input
                  type="text"
                  value={cronExpr}
                  onChange={(e) => setCronExpr(e.target.value)}
                  placeholder="0 2 * * *"
                  className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
                />
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-theme-secondary mb-1">
                {L('Scan Profile', 'Profilo di Scansione')}
              </label>
              <select
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
                className="input-industrial w-full px-2.5 py-1.5 text-xs"
              >
                <option value="Full Purple Assessment (Rete + Web)" className="bg-panel text-theme-primary">{L('Full Purple Assessment', 'Full Purple Assessment')}</option>
                <option value="Quick Network Discovery" className="bg-panel text-theme-primary">Quick Network Discovery</option>
                <option value="Web Application & OWASP Audit" className="bg-panel text-theme-primary">Web Application & OWASP</option>
                <option value="SSL/TLS & Crypto Check" className="bg-panel text-theme-primary">SSL/TLS & Crypto Check</option>
              </select>
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-theme-subtle">
            <button
              type="button"
              onClick={() => setIsCreating(false)}
              className="btn-secondary px-3 py-1.5 text-xs font-medium"
            >
              {L('Cancel', 'Annulla')}
            </button>
            <button
              type="submit"
              className="btn-primary px-3.5 py-1.5 text-xs font-semibold"
            >
              {L('Save Rule', 'Salva Regola')}
            </button>
          </div>
        </form>
      )}

      {/* Schedules List */}
      <div className="space-y-2.5">
        {filteredSchedules.length === 0 ? (
          <div className="card-industrial p-8 text-center text-theme-muted">
            <Clock className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <div className="text-xs font-semibold text-theme-secondary">
              {L('No active schedules', 'Nessuna schedulazione attiva')}
            </div>
            <p className="text-[11px] text-theme-muted mt-0.5">
              {L(
                'Configure an automatic periodic scan to start continuous monitoring.',
                'Configura una scansione periodica automatica per iniziare il monitoraggio continuo.'
              )}
            </p>
          </div>
        ) : (
          filteredSchedules.map((sched) => {
            const org = organizations.find((o) => o.id === sched.org_id);
            const frequencyLabel = {
              hourly: L('Hourly', 'Ogni Ora'),
              daily: L('Daily', 'Giornaliera'),
              weekly: L('Weekly', 'Settimanale'),
              monthly: L('Monthly', 'Mensile'),
              cron: 'Cron',
            }[sched.frequency] || sched.frequency;

            return (
              <div
                key={sched.id}
                className="card-industrial p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-xs text-theme-primary">{sched.name}</span>
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${sched.enabled ? 'bg-emerald-950/30 border-emerald-600 text-emerald-400' : 'bg-subtle border-theme text-theme-muted'}`}>
                      {sched.enabled ? L('ACTIVE', 'ATTIVA') : L('PAUSED', 'SOSPESA')}
                    </span>
                    <span className="text-[10px] font-mono text-theme-muted uppercase">
                      {frequencyLabel} {sched.time_of_day ? `@ ${sched.time_of_day}` : ''}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 text-[11px] text-theme-secondary font-mono">
                    <span className="text-theme-accent font-semibold">{org?.name || 'MSP'}</span>
                    <span>•</span>
                    <span className="truncate max-w-xs">{sched.targets}</span>
                    <span>•</span>
                    <span>{L('Next:', 'Prossima:')} {sched.next_run || L('Scheduled', 'Pianificata')}</span>
                  </div>
                </div>

                <div className="flex items-center space-x-1.5 self-end sm:self-center">
                  <button
                    onClick={() => handleRunNow(sched.id)}
                    className="btn-secondary px-2.5 py-1 text-xs font-semibold flex items-center space-x-1"
                    title={L('Run scan now', 'Esegui scansione adesso')}
                  >
                    <Play className="w-3 h-3 fill-current text-theme-accent" />
                    <span>{L('Run Now', 'Esegui Ora')}</span>
                  </button>

                  <button
                    onClick={() => handleToggleEnable(sched)}
                    className={`btn-secondary p-1.5 ${sched.enabled ? 'text-emerald-400' : 'text-theme-muted'}`}
                    title={sched.enabled ? L('Disable', 'Disattiva') : L('Enable', 'Attiva')}
                  >
                    <Power className="w-3.5 h-3.5" />
                  </button>

                  <button
                    onClick={() => setDeleteTargetId(sched.id)}
                    className="btn-secondary p-1.5 text-theme-muted hover:text-red-400"
                    title={L('Delete schedule', 'Elimina pianificazione')}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Delete Confirmation Modal */}
      <ConfirmModal
        isOpen={deleteTargetId !== null}
        title={L('Delete Schedule', 'Elimina Pianificazione')}
        description={L('Are you sure you want to remove this periodic scan rule? The scheduled automation will be stopped.', "Sei sicuro di voler rimuovere questa regola di scansione periodica? L'automazione pianificata verrà interrotta.")}
        confirmText={L('Delete Schedule', 'Elimina Schedulazione')}
        isDestructive={true}
        isLoading={isDeleting}
        onCancel={() => setDeleteTargetId(null)}
        onConfirm={confirmDeleteSchedule}
      />
    </div>
  );
};
