import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Globe, Play, Loader2, CheckCircle, AlertCircle } from 'lucide-react';
import toast from 'react-hot-toast';

interface DomainInvestigationModalProps {
  isOpen: boolean;
  onClose: () => void;
  apiUrl?: string;
}

export const DomainInvestigationModal: React.FC<DomainInvestigationModalProps> = ({ 
  isOpen, 
  onClose,
  apiUrl = 'http://localhost:8000'
}) => {
  const [domain, setDomain] = useState('');
  const [isRunning, setIsRunning] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');

  const handleRun = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setResult(null);
    setIsRunning(true);

    try {
      // Validate domain format
      const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z]{2,})+$/;
      if (!domainRegex.test(domain)) {
        throw new Error('Please enter a valid domain name (e.g., example.com)');
      }

      const response = await fetch(`${apiUrl}/api/modules/domain/run`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('auth_token') || ''}`
        },
        body: JSON.stringify({ 
          target: domain,
          options: {
            dns_lookup: true,
            whois_lookup: true,
            subdomain_scan: true
          }
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Investigation failed' }));
        throw new Error(errorData.detail || 'Failed to run domain investigation');
      }

      const data = await response.json();
      setResult(data);
      toast.success('Domain investigation completed!');
    } catch (err: any) {
      setError(err.message || 'Investigation failed. Please try again.');
      toast.error(err.message || 'Investigation failed');
    } finally {
      setIsRunning(false);
    }
  };

  const handleClose = () => {
    setDomain('');
    setResult(null);
    setError('');
    onClose();
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        {/* Backdrop */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="absolute inset-0 bg-black/60 backdrop-blur-sm"
          onClick={handleClose}
        />

        {/* Modal */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          className="relative bg-white rounded-xl shadow-2xl max-w-2xl w-full max-h-[80vh] overflow-hidden"
        >
          {/* Header */}
          <div className="bg-gradient-to-r from-blue-600 to-cyan-600 px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className="bg-white/20 p-2 rounded-lg">
                  <Globe className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">Domain Investigation</h2>
                  <p className="text-white/80 text-sm">DNS, WHOIS & subdomain analysis</p>
                </div>
              </div>
              <button
                onClick={handleClose}
                className="text-white/80 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Body */}
          <div className="p-6 overflow-y-auto max-h-[calc(80vh-140px)]">
            <form onSubmit={handleRun} className="space-y-4">
              {error && (
                <div className="flex items-center space-x-2 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg">
                  <AlertCircle className="w-5 h-5 flex-shrink-0" />
                  <span className="text-sm">{error}</span>
                </div>
              )}

              {/* Domain Input */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Domain Name
                </label>
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="example.com"
                  required
                  disabled={isRunning}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white text-gray-900 disabled:opacity-50 disabled:cursor-not-allowed"
                />
                <p className="text-sm text-gray-500 mt-1">
                  Enter the domain you want to investigate (without http:// or https://)
                </p>
              </div>

              {/* Investigation Options */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-3">
                  Investigation Options
                </label>
                <div className="space-y-2">
                  <label className="flex items-center space-x-3 p-3 bg-gray-50 rounded-lg">
                    <input
                      type="checkbox"
                      defaultChecked
                      disabled={isRunning}
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <div>
                      <span className="text-sm font-medium text-gray-900">DNS Lookup</span>
                      <p className="text-xs text-gray-500">Retrieve DNS records (A, AAAA, MX, TXT, etc.)</p>
                    </div>
                  </label>
                  <label className="flex items-center space-x-3 p-3 bg-gray-50 rounded-lg">
                    <input
                      type="checkbox"
                      defaultChecked
                      disabled={isRunning}
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <div>
                      <span className="text-sm font-medium text-gray-900">WHOIS Lookup</span>
                      <p className="text-xs text-gray-500">Get domain registration information</p>
                    </div>
                  </label>
                  <label className="flex items-center space-x-3 p-3 bg-gray-50 rounded-lg">
                    <input
                      type="checkbox"
                      defaultChecked
                      disabled={isRunning}
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <div>
                      <span className="text-sm font-medium text-gray-900">Subdomain Discovery</span>
                      <p className="text-xs text-gray-500">Find subdomains associated with the target</p>
                    </div>
                  </label>
                </div>
              </div>

              {/* Results */}
              {result && (
                <div className="mt-6 p-4 bg-green-50 border border-green-200 rounded-lg">
                  <div className="flex items-center space-x-2 mb-3">
                    <CheckCircle className="w-5 h-5 text-green-600" />
                    <span className="font-medium text-green-900">Investigation Complete</span>
                  </div>
                  <div className="text-sm text-gray-700 space-y-2">
                    <p><strong>Status:</strong> {result.status || 'Completed'}</p>
                    <p><strong>Target:</strong> {result.target || domain}</p>
                    {result.message && <p>{result.message}</p>}
                  </div>
                  {result.results && (
                    <div className="mt-3 p-3 bg-white rounded border border-gray-200">
                      <pre className="text-xs overflow-x-auto">
                        {JSON.stringify(result.results, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </form>
          </div>

          {/* Footer */}
          <div className="border-t border-gray-200 px-6 py-4 bg-gray-50">
            <div className="flex space-x-3">
              <button
                onClick={handleClose}
                disabled={isRunning}
                className="flex-1 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-100 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {result ? 'Close' : 'Cancel'}
              </button>
              <button
                onClick={handleRun}
                disabled={isRunning || !domain}
                className="flex-1 px-4 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 text-white rounded-lg hover:from-blue-700 hover:to-cyan-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2"
              >
                {isRunning ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    <span>Running...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-5 h-5" />
                    <span>Run Investigation</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
