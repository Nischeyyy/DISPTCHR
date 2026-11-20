import { lazy, Suspense, useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout.jsx';
import { api } from './api/client.js';

const Login = lazy(() => import('./pages/Login.jsx'));
const Dashboard = lazy(() => import('./pages/Dashboard.jsx'));
const Guards = lazy(() => import('./pages/Guards.jsx'));
const BadgeVerify = lazy(() => import('./pages/BadgeVerify.jsx'));
const Sites = lazy(() => import('./pages/Sites.jsx'));
const Shifts = lazy(() => import('./pages/Shifts.jsx'));
const OpenShifts = lazy(() => import('./pages/OpenShifts.jsx'));
const ShiftSwaps = lazy(() => import('./pages/ShiftSwaps.jsx'));
const Timeclock = lazy(() => import('./pages/Timeclock.jsx'));
const Incidents = lazy(() => import('./pages/Incidents.jsx'));
const SosAlerts = lazy(() => import('./pages/SosAlerts.jsx'));
const Payroll = lazy(() => import('./pages/Payroll.jsx'));
const Announcements = lazy(() => import('./pages/Announcements.jsx'));
const Compliance = lazy(() => import('./pages/Compliance.jsx'));
const LiveLocations = lazy(() => import('./pages/LiveLocations.jsx'));

// Pathless layout wrapper — only protects its children, doesn't compete with "/"
function ProtectedLayout() {
  const [state, setState] = useState('checking');
  useEffect(() => {
    let active = true;
    api.me().then((user) => {
      if (!active) return;
      localStorage.setItem('mgr_user', JSON.stringify(user));
      setState('authorized');
    }).catch(() => {
      if (!active) return;
      localStorage.removeItem('mgr_user');
      setState('denied');
    });
    return () => { active = false; };
  }, []);
  if (state === 'checking') return <div className="min-h-screen grid place-items-center text-sm text-gray-500">Verifying your session…</div>;
  if (state === 'denied') return <Navigate to="/" replace />;
  return <Layout />;
}

export default function App() {
  return (
    <BrowserRouter basename="/manager">
      <Suspense fallback={<div className="min-h-screen grid place-items-center text-sm text-gray-500">Loading Manager Portal…</div>}>
      <Routes>
        {/* Public */}
        <Route path="/" element={<Login />} />

        {/* Protected — pathless layout route, children define their own paths */}
        <Route element={<ProtectedLayout />}>
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="guards" element={<Guards />} />
          <Route path="badge-verify" element={<BadgeVerify />} />
          <Route path="sites" element={<Sites />} />
          <Route path="shifts" element={<Shifts />} />
          <Route path="open-shifts" element={<OpenShifts />} />
          <Route path="swaps" element={<ShiftSwaps />} />
          <Route path="timeclock" element={<Timeclock />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="sos" element={<SosAlerts />} />
          <Route path="payroll" element={<Payroll />} />
          <Route path="announcements" element={<Announcements />} />
          <Route path="compliance" element={<Compliance />} />
          <Route path="live" element={<LiveLocations />} />
        </Route>

        {/* Catch-all redirect */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
