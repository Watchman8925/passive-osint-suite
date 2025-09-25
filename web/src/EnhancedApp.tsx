import React, { useState, useEffect } from 'react';
import {
  HomeIcon,
  DocumentMagnifyingGlassIcon,
  CubeIcon,
  CpuChipIcon,
  CogIcon,
  MagnifyingGlassIcon,
  EnvelopeIcon,
  GlobeAltIcon,
  BuildingOfficeIcon,
  CurrencyDollarIcon,
  PaperAirplaneIcon,
  PhotoIcon,
  LinkIcon,
  EyeIcon,
  ShieldCheckIcon,
  ServerIcon,
  PlayIcon,
  ChartBarIcon,
  ClockIcon,
  UserGroupIcon,
  LightBulbIcon,
  FireIcon,
  SparklesIcon,
  BoltIcon
} from '@heroicons/react/24/outline';

const EnhancedApp: React.FC = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [apiStatus, setApiStatus] = useState('checking');
  const [llmStatus, setLlmStatus] = useState('offline');
  const [selectedModule, setSelectedModule] = useState<string | null>(null);
  const [analysisQuery, setAnalysisQuery] = useState('');
  const [analysisResult, setAnalysisResult] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [stats, setStats] = useState({
    totalInvestigations: 47,
    activeModules: 12,
    aiQueries: 156,
    successRate: 94
  });

  useEffect(() => {
    // Check API health
    fetch('http://localhost:8000/health')
      .then(res => res.json())
      .then(() => setApiStatus('online'))
      .catch(() => setApiStatus('offline'));

    // Check LLM status
    fetch('http://localhost:8001/ai/status')
      .then(res => res.json())
      .then(() => setLlmStatus('online'))
      .catch(() => setLlmStatus('offline'));
  }, []);

  const handleAnalysis = async () => {
    if (!analysisQuery.trim()) return;
    
    setIsAnalyzing(true);
    try {
      const response = await fetch('http://localhost:8001/ai/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: analysisQuery })
      });
      const result = await response.json();
      setAnalysisResult(result.analysis || 'Analysis completed successfully');
    } catch (error) {
      setAnalysisResult('Analysis service temporarily unavailable. Please try again.');
    }
    setIsAnalyzing(false);
  };

  const handleModuleClick = async (moduleId: string) => {
    setSelectedModule(moduleId);
    try {
      const response = await fetch(`http://localhost:8001/modules/${moduleId}/status`);
      const result = await response.json();
      console.log(`${moduleId} module status:`, result);
    } catch (error) {
      console.log(`${moduleId} module loading...`);
    }
  };

  const osintModules = [
    {
      id: 'domain',
      name: 'Domain Intelligence',
      icon: GlobeAltIcon,
      description: 'DNS, WHOIS, Subdomain Analysis',
      color: 'from-blue-500 to-cyan-500',
      bgColor: 'bg-blue-500/10',
      borderColor: 'border-blue-500/20'
    },
    {
      id: 'email',
      name: 'Email Intelligence',
      icon: EnvelopeIcon,
      description: 'Email Investigation & Breach Analysis',
      color: 'from-green-500 to-emerald-500',
      bgColor: 'bg-green-500/10',
      borderColor: 'border-green-500/20'
    },
    {
      id: 'ip',
      name: 'IP Intelligence',
      icon: ServerIcon,
      description: 'Network & Geolocation Analysis',
      color: 'from-purple-500 to-violet-500',
      bgColor: 'bg-purple-500/10',
      borderColor: 'border-purple-500/20'
    },
    {
      id: 'company',
      name: 'Company Intelligence',
      icon: BuildingOfficeIcon,
      description: 'Corporate Intelligence Gathering',
      color: 'from-orange-500 to-red-500',
      bgColor: 'bg-orange-500/10',
      borderColor: 'border-orange-500/20'
    },
    {
      id: 'crypto',
      name: 'Crypto Intelligence',
      icon: CurrencyDollarIcon,
      description: 'Blockchain & Cryptocurrency Analysis',
      color: 'from-yellow-500 to-amber-500',
      bgColor: 'bg-yellow-500/10',
      borderColor: 'border-yellow-500/20'
    },
    {
      id: 'flight',
      name: 'Flight Intelligence',
      icon: PaperAirplaneIcon,
      description: 'Aviation Tracking & Analysis',
      color: 'from-indigo-500 to-blue-500',
      bgColor: 'bg-indigo-500/10',
      borderColor: 'border-indigo-500/20'
    },
    {
      id: 'media',
      name: 'Media Forensics',
      icon: PhotoIcon,
      description: 'Image & Video Analysis',
      color: 'from-pink-500 to-rose-500',
      bgColor: 'bg-pink-500/10',
      borderColor: 'border-pink-500/20'
    },
    {
      id: 'network',
      name: 'Network Intelligence',
      icon: LinkIcon,
      description: 'Infrastructure Mapping',
      color: 'from-teal-500 to-cyan-500',
      bgColor: 'bg-teal-500/10',
      borderColor: 'border-teal-500/20'
    },
    {
      id: 'conspiracy',
      name: 'Conspiracy Analysis',
      icon: EyeIcon,
      description: 'Evidence-Based Pattern Analysis',
      color: 'from-red-500 to-pink-500',
      bgColor: 'bg-red-500/10',
      borderColor: 'border-red-500/20'
    },
    {
      id: 'patterns',
      name: 'Pattern Detection',
      icon: SparklesIcon,
      description: 'Hidden Pattern Discovery',
      color: 'from-violet-500 to-purple-500',
      bgColor: 'bg-violet-500/10',
      borderColor: 'border-violet-500/20'
    },
    {
      id: 'cross-ref',
      name: 'Cross Reference',
      icon: BoltIcon,
      description: 'Multi-Source Correlation',
      color: 'from-emerald-500 to-teal-500',
      bgColor: 'bg-emerald-500/10',
      borderColor: 'border-emerald-500/20'
    },
    {
      id: 'anonymity',
      name: 'Anonymity Grid',
      icon: ShieldCheckIcon,
      description: 'Privacy & Security Analysis',
      color: 'from-slate-500 to-gray-500',
      bgColor: 'bg-slate-500/10',
      borderColor: 'border-slate-500/20'
    }
  ];

  const sidebarItems = [
    { id: 'dashboard', name: 'Dashboard', icon: HomeIcon },
    { id: 'investigations', name: 'Investigations', icon: DocumentMagnifyingGlassIcon },
    { id: 'modules', name: 'OSINT Modules', icon: CubeIcon },
    { id: 'ai-analysis', name: 'AI Analysis', icon: CpuChipIcon },
    { id: 'settings', name: 'Settings', icon: CogIcon }
  ];

  const renderDashboard = () => (
    <div className="space-y-8">
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-gradient-to-br from-blue-500/20 to-cyan-500/20 border border-blue-500/30 rounded-xl p-6 hover:scale-105 transition-transform">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-300 text-sm font-medium">Total Investigations</p>
              <p className="text-3xl font-bold text-white">{stats.totalInvestigations}</p>
            </div>
            <ChartBarIcon className="w-8 h-8 text-blue-400" />
          </div>
        </div>
        
        <div className="bg-gradient-to-br from-green-500/20 to-emerald-500/20 border border-green-500/30 rounded-xl p-6 hover:scale-105 transition-transform">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-green-300 text-sm font-medium">Active Modules</p>
              <p className="text-3xl font-bold text-white">{stats.activeModules}</p>
            </div>
            <CubeIcon className="w-8 h-8 text-green-400" />
          </div>
        </div>
        
        <div className="bg-gradient-to-br from-purple-500/20 to-violet-500/20 border border-purple-500/30 rounded-xl p-6 hover:scale-105 transition-transform">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-purple-300 text-sm font-medium">AI Queries</p>
              <p className="text-3xl font-bold text-white">{stats.aiQueries}</p>
            </div>
            <CpuChipIcon className="w-8 h-8 text-purple-400" />
          </div>
        </div>
        
        <div className="bg-gradient-to-br from-orange-500/20 to-red-500/20 border border-orange-500/30 rounded-xl p-6 hover:scale-105 transition-transform">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-orange-300 text-sm font-medium">Success Rate</p>
              <p className="text-3xl font-bold text-white">{stats.successRate}%</p>
            </div>
            <FireIcon className="w-8 h-8 text-orange-400" />
          </div>
        </div>
      </div>

      {/* System Status */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
        <h3 className="text-xl font-semibold mb-4 flex items-center">
          <ServerIcon className="w-6 h-6 mr-2 text-blue-400" />
          System Status
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="flex items-center justify-between">
            <span className="text-slate-300">API Server</span>
            <span className={`px-3 py-1 rounded-full text-sm font-medium ${
              apiStatus === 'online' ? 'bg-green-500/20 text-green-400' : 
              apiStatus === 'offline' ? 'bg-red-500/20 text-red-400' : 
              'bg-yellow-500/20 text-yellow-400'
            }`}>
              {apiStatus === 'online' ? '🟢 Online' : apiStatus === 'offline' ? '🔴 Offline' : '🟡 Checking'}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-300">AI Engine</span>
            <span className={`px-3 py-1 rounded-full text-sm font-medium ${
              llmStatus === 'online' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
            }`}>
              {llmStatus === 'online' ? '🟢 Online' : '🔴 Offline'}
            </span>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
        <h3 className="text-xl font-semibold mb-4 flex items-center">
          <LightBulbIcon className="w-6 h-6 mr-2 text-yellow-400" />
          Quick Actions
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button
            onClick={() => setActiveTab('investigations')}
            className="bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/30 rounded-lg p-4 text-left transition-all hover:scale-105"
          >
            <DocumentMagnifyingGlassIcon className="w-6 h-6 text-blue-400 mb-2" />
            <div className="text-white font-medium">New Investigation</div>
            <div className="text-slate-400 text-sm">Start a new case</div>
          </button>
          
          <button
            onClick={() => setActiveTab('ai-analysis')}
            className="bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 rounded-lg p-4 text-left transition-all hover:scale-105"
          >
            <CpuChipIcon className="w-6 h-6 text-purple-400 mb-2" />
            <div className="text-white font-medium">AI Analysis</div>
            <div className="text-slate-400 text-sm">Get AI insights</div>
          </button>
          
          <button
            onClick={() => setActiveTab('modules')}
            className="bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 rounded-lg p-4 text-left transition-all hover:scale-105"
          >
            <CubeIcon className="w-6 h-6 text-green-400 mb-2" />
            <div className="text-white font-medium">Explore Modules</div>
            <div className="text-slate-400 text-sm">Browse OSINT tools</div>
          </button>
        </div>
      </div>
    </div>
  );

  const renderModules = () => (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">OSINT Modules</h2>
        <span className="bg-blue-500/20 text-blue-400 px-3 py-1 rounded-full text-sm">
          {osintModules.length} Modules Available
        </span>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {osintModules.map((module) => {
          const IconComponent = module.icon;
          return (
            <button
              key={module.id}
              onClick={() => handleModuleClick(module.id)}
              className={`${module.bgColor} ${module.borderColor} border rounded-xl p-6 text-left hover:scale-105 transition-all duration-300 group ${
                selectedModule === module.id ? 'ring-2 ring-blue-500' : ''
              }`}
            >
              <div className="flex items-center justify-between mb-4">
                <div className={`bg-gradient-to-r ${module.color} p-3 rounded-lg`}>
                  <IconComponent className="w-6 h-6 text-white" />
                </div>
                <PlayIcon className="w-5 h-5 text-slate-400 group-hover:text-white transition-colors" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">{module.name}</h3>
              <p className="text-slate-400 text-sm">{module.description}</p>
              {selectedModule === module.id && (
                <div className="mt-3 text-green-400 text-sm font-medium">✓ Module Selected</div>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );

  const renderAIAnalysis = () => (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">AI Analysis Center</h2>
        <span className={`px-3 py-1 rounded-full text-sm font-medium ${
          llmStatus === 'online' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
        }`}>
          {llmStatus === 'online' ? '🤖 AI Ready' : '🤖 AI Offline'}
        </span>
      </div>

      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
        <h3 className="text-lg font-semibold mb-4">Query Analysis</h3>
        <div className="space-y-4">
          <textarea
            value={analysisQuery}
            onChange={(e) => setAnalysisQuery(e.target.value)}
            placeholder="Enter your OSINT query for AI analysis..."
            className="w-full h-32 bg-slate-700 border border-slate-600 rounded-lg p-4 text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
          <button
            onClick={handleAnalysis}
            disabled={isAnalyzing || !analysisQuery.trim()}
            className="bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600 disabled:opacity-50 disabled:cursor-not-allowed px-6 py-3 rounded-lg font-medium text-white transition-all hover:scale-105"
          >
            {isAnalyzing ? (
              <>
                <div className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                Analyzing...
              </>
            ) : (
              <>
                <CpuChipIcon className="w-5 h-5 inline mr-2" />
                Analyze with AI
              </>
            )}
          </button>
        </div>
      </div>

      {analysisResult && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
          <h3 className="text-lg font-semibold mb-4 flex items-center">
            <SparklesIcon className="w-5 h-5 mr-2 text-yellow-400" />
            Analysis Results
          </h3>
          <div className="bg-slate-900/50 border border-slate-600 rounded-lg p-4">
            <pre className="text-slate-300 whitespace-pre-wrap text-sm">{analysisResult}</pre>
          </div>
        </div>
      )}
    </div>
  );

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return renderDashboard();
      case 'modules':
        return renderModules();
      case 'ai-analysis':
        return renderAIAnalysis();
      case 'investigations':
        return (
          <div className="text-center py-12">
            <DocumentMagnifyingGlassIcon className="w-16 h-16 text-slate-600 mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-white mb-2">Investigations Module</h2>
            <p className="text-slate-400">Case management system coming soon...</p>
          </div>
        );
      case 'settings':
        return (
          <div className="text-center py-12">
            <CogIcon className="w-16 h-16 text-slate-600 mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-white mb-2">Settings</h2>
            <p className="text-slate-400">Configuration panel coming soon...</p>
          </div>
        );
      default:
        return renderDashboard();
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <div className="flex">
        {/* Sidebar */}
        <div className="w-64 bg-slate-800/50 backdrop-blur-sm border-r border-slate-700 min-h-screen">
          <div className="p-6">
            <div className="flex items-center space-x-3 mb-8">
              <div className="bg-gradient-to-r from-blue-500 to-purple-500 p-2 rounded-lg">
                <MagnifyingGlassIcon className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">OSINT Suite</h1>
                <p className="text-xs text-slate-400">Professional Intelligence</p>
              </div>
            </div>

            <nav className="space-y-2">
              {sidebarItems.map((item) => {
                const IconComponent = item.icon;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveTab(item.id)}
                    className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-left transition-all hover:scale-105 ${
                      activeTab === item.id
                        ? 'bg-gradient-to-r from-blue-500/20 to-purple-500/20 border border-blue-500/30 text-white'
                        : 'text-slate-400 hover:text-white hover:bg-slate-700/50'
                    }`}
                  >
                    <IconComponent className="w-5 h-5" />
                    <span className="font-medium">{item.name}</span>
                  </button>
                );
              })}
            </nav>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1">
          <div className="max-w-7xl mx-auto p-8">
            {renderContent()}
          </div>
        </div>
      </div>
    </div>
  );
};

export default EnhancedApp;