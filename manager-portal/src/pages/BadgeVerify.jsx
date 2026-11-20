import { useEffect, useRef, useState } from 'react';
import { CheckCircle2, QrCode, RotateCcw, ShieldAlert } from 'lucide-react';
import { api } from '../api/client.js';

export default function BadgeVerify() {
  const scannerRef = useRef(null);
  const handledRef = useRef(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [starting, setStarting] = useState(true);

  async function verify(token) {
    if (handledRef.current) return;
    handledRef.current = true;
    try {
      const response = await api.verifyEmployeeBadge(token);
      setResult(response.employee);
      setError('');
      await scannerRef.current?.stop().catch(() => {});
    } catch (reason) {
      handledRef.current = false;
      setError(reason.message || 'This employee ID could not be verified.');
    }
  }

  useEffect(() => {
    let mounted = true;
    async function start() {
      try {
        const { Html5Qrcode } = await import('html5-qrcode');
        if (!mounted) return;
        const scanner = new Html5Qrcode('employee-badge-reader');
        scannerRef.current = scanner;
        await scanner.start(
          { facingMode: 'environment' },
          { fps: 10, qrbox: { width: 240, height: 240 } },
          (decodedText) => verify(decodedText),
          () => {},
        );
      } catch (reason) {
        if (mounted) setError(reason?.message || 'Camera access is unavailable. Check browser permissions.');
      } finally {
        if (mounted) setStarting(false);
      }
    }
    start();
    return () => {
      mounted = false;
      const scanner = scannerRef.current;
      if (scanner?.isScanning) scanner.stop().then(() => scanner.clear()).catch(() => {});
      else if (scanner) scanner.clear();
    };
  }, []);

  function reset() {
    window.location.reload();
  }

  return <div className="max-w-3xl mx-auto">
    <div className="mb-6">
      <h1 className="text-2xl font-bold text-gray-900">Verify Employee ID</h1>
      <p className="text-sm text-gray-500 mt-1">Scan the live QR code in the guard’s Disptchr wallet. Codes expire after five minutes.</p>
    </div>
    <div className="card p-5">
      {!result && <div id="employee-badge-reader" className="overflow-hidden rounded-xl border border-gray-200 min-h-64" />}
      {starting && <p className="text-sm text-gray-500 mt-3">Starting camera…</p>}
      {error && <div className="mt-4 flex gap-3 rounded-xl border border-red-200 bg-red-50 p-4 text-red-700"><ShieldAlert className="shrink-0" size={20} /><span>{error}</span></div>}
      {result && <div className="rounded-xl border border-green-200 bg-green-50 p-6">
        <div className="flex items-center gap-3 text-green-700 mb-5"><CheckCircle2 size={28} /><strong className="text-lg">Employee ID verified</strong></div>
        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
          <div><dt className="text-gray-500">Employee</dt><dd className="font-semibold text-gray-900">{result.full_name}</dd></div>
          <div><dt className="text-gray-500">Employee number</dt><dd className="font-semibold text-gray-900">{result.employee_number || 'Not assigned'}</dd></div>
          <div><dt className="text-gray-500">Licence</dt><dd className="font-semibold text-gray-900">{result.licence_number || 'Not on file'}</dd></div>
          <div><dt className="text-gray-500">Employment status</dt><dd className="font-semibold text-gray-900">{result.employment_status || 'Not set'}</dd></div>
        </dl>
      </div>}
      <button type="button" onClick={reset} className="btn-secondary mt-5 flex items-center gap-2"><RotateCcw size={16} />Scan another ID</button>
    </div>
    <div className="mt-4 flex items-start gap-2 text-xs text-gray-400"><QrCode size={15} className="shrink-0" /><span>The code is cryptographically signed and checked against the active employee database; screenshots expire automatically.</span></div>
  </div>;
}
