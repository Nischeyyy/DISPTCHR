import { AlertTriangle, RefreshCw } from 'lucide-react';

export default function LoadFailure({ message, onRetry }) {
  return (
    <div role="alert" className="card py-12 text-center flex flex-col items-center">
      <AlertTriangle size={30} className="text-red-500" />
      <h2 className="mt-3 text-base font-bold text-gray-900">Unable to load this page</h2>
      <p className="mt-2 max-w-md text-sm text-gray-600">{message || 'The server did not return the requested information.'}</p>
      <button type="button" onClick={onRetry} className="btn-primary mt-5 inline-flex items-center gap-2">
        <RefreshCw size={15} /> Try again
      </button>
    </div>
  );
}
