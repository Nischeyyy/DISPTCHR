import { useEffect, useState } from 'react';
import { api } from '../api/client.js';
import PageHeader from '../components/PageHeader.jsx';
import Modal from '../components/Modal.jsx';
import EmptyState from '../components/EmptyState.jsx';
import LoadFailure from '../components/LoadFailure.jsx';
import { MapPin, Plus, Edit2, Trash2, Building } from 'lucide-react';
import { sitePayload } from '../domain/adminForms.js';

const EMPTY = {
  name: '', client_name: '', address: '', city: '', latitude: '', longitude: '',
  geofence_radius_m: 200, supervisor: '', supervisor_phone: '', instructions: '',
};

export default function Sites() {
  const [sites, setSites] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(null);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState(EMPTY);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [loadError, setLoadError] = useState('');

  async function load() {
    try {
      const d = await api.sites();
      setSites(d.sites || []);
      setLoadError('');
    } catch (reason) {
      setLoadError(reason.message || 'Unable to load sites.');
    } finally { setLoading(false); }
  }
  useEffect(() => { load(); }, []);

  function openCreate() { setForm(EMPTY); setEditing(null); setError(''); setModal('open'); }
  function openEdit(s) {
    setForm({
      name: s.name || '', client_name: s.client_name || '', address: s.address || '', city: s.city || '',
      latitude: s.latitude ?? '', longitude: s.longitude ?? '', geofence_radius_m: s.geofence_radius_m || 200,
      supervisor: s.supervisor || '', supervisor_phone: s.supervisor_phone || '', instructions: s.instructions || '',
    });
    setEditing(s); setError(''); setModal('open');
  }

  async function handleSave(e) {
    e.preventDefault(); setSaving(true); setError('');
    try {
      const body = sitePayload(form);
      editing ? await api.updateSite(editing.id, body) : await api.createSite(body);
      setModal(null); await load();
    } catch (err) { setError(err.message); } finally { setSaving(false); }
  }

  async function handleDelete(s) {
    if (!confirm(`Delete site "${s.name}"?`)) return;
    try { await api.deleteSite(s.id); await load(); } catch (err) { alert(err.message); }
  }

  const f = (k) => (e) => setForm(p => ({ ...p, [k]: e.target.value }));

  return (
    <div>
      <PageHeader title="Sites" subtitle={`${sites.length} client site${sites.length !== 1 ? 's' : ''}`}
        action={<button className="btn-primary flex items-center gap-2" onClick={openCreate}><Plus size={16} /> Add Site</button>} />

      {loading ? <div className="text-gray-400 text-sm">Loading…</div> : loadError ? (
        <LoadFailure message={loadError} onRetry={() => { setLoading(true); load(); }} />
      ) : (
        !sites.length ? <EmptyState icon={MapPin} title="No sites yet" subtitle="Add your first client site to get started" /> : (
          <div className="grid sm:grid-cols-2 xl:grid-cols-3 gap-4">
            {sites.map(s => (
              <div key={s.id} className="card flex flex-col justify-between group hover:border-gray-300 transition-colors cursor-pointer">
                <div>
                  <div className="flex items-start justify-between gap-2 mb-3">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-gray-50 border border-gray-100 flex items-center justify-center flex-shrink-0 text-gray-400">
                        <Building size={20} />
                      </div>
                      <div>
                        <p className="font-semibold text-gray-900 leading-tight">{s.name}</p>
                        {s.client_name && <p className="text-xs text-gray-500 mt-0.5">{s.client_name}</p>}
                      </div>
                    </div>
                    <div className="flex gap-1 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button onClick={() => openEdit(s)} className="text-gray-400 hover:text-gray-900 p-1.5 rounded transition-colors"><Edit2 size={14} /></button>
                      <button onClick={() => handleDelete(s)} className="text-gray-400 hover:text-red-500 p-1.5 rounded transition-colors"><Trash2 size={14} /></button>
                    </div>
                  </div>
                  <div className="text-sm text-gray-600 space-y-1.5">
                    {s.address && (
                      <div className="flex items-start gap-2">
                         <MapPin size={14} className="text-gray-400 mt-0.5 flex-shrink-0" />
                         <p>{s.address}{s.city ? `, ${s.city}` : ''}</p>
                      </div>
                    )}
                    {Number.isFinite(s.latitude) && Number.isFinite(s.longitude) && <p className="font-mono text-xs text-gray-500 pl-6">{Number(s.latitude).toFixed(5)}, {Number(s.longitude).toFixed(5)} · {s.geofence_radius_m}m radius</p>}
                    {s.supervisor && <p className="text-xs text-gray-500 pl-6">Supervisor: {s.supervisor}{s.supervisor_phone ? ` · ${s.supervisor_phone}` : ''}</p>}
                  </div>
                </div>
                {s.instructions && (
                  <div className="mt-4 pt-4 border-t border-gray-100">
                    <p className="text-xs text-gray-500 italic line-clamp-2">{s.instructions}</p>
                  </div>
                )}
              </div>
            ))}
          </div>
        )
      )}

      {modal && (
        <Modal title={editing ? `Edit — ${editing.name}` : 'Add Site'} onClose={() => setModal(null)}>
          <form onSubmit={handleSave} className="space-y-4">
            {error && <p className="text-red-600 text-sm bg-red-50 border border-red-200 rounded-lg px-3 py-2">{error}</p>}
            <div className="grid grid-cols-2 gap-4">
              <div className="col-span-2"><label className="label">Site Name</label><input className="input" value={form.name} onChange={f('name')} required /></div>
              <div className="col-span-2"><label className="label">Client Name</label><input className="input" value={form.client_name} onChange={f('client_name')} /></div>
              <div className="col-span-2"><label className="label">Address</label><input className="input" value={form.address} onChange={f('address')} /></div>
              <div><label className="label">City</label><input className="input" value={form.city} onChange={f('city')} /></div>
              <div><label className="label">Geofence Radius (m)</label><input type="number" className="input" value={form.geofence_radius_m} onChange={f('geofence_radius_m')} min={25} max={10000} required /></div>
              <div><label className="label">Latitude</label><input type="number" step="any" min={-90} max={90} className="input" value={form.latitude} onChange={f('latitude')} required /></div>
              <div><label className="label">Longitude</label><input type="number" step="any" min={-180} max={180} className="input" value={form.longitude} onChange={f('longitude')} required /></div>
              <div><label className="label">Site Supervisor</label><input className="input" value={form.supervisor} onChange={f('supervisor')} required /></div>
              <div><label className="label">Supervisor Phone</label><input type="tel" className="input" value={form.supervisor_phone} onChange={f('supervisor_phone')} required /></div>
              <div className="col-span-2"><label className="label">Guard Instructions</label><textarea className="input resize-none" rows={3} value={form.instructions} onChange={f('instructions')} /></div>
            </div>
            <div className="flex justify-end gap-3 pt-2">
              <button type="button" className="btn-secondary" onClick={() => setModal(null)}>Cancel</button>
              <button type="submit" className="btn-primary" disabled={saving}>{saving ? 'Saving…' : 'Save'}</button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
}
