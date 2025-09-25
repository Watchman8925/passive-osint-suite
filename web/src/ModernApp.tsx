import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import GeoMap from './components/geo/GeoMap';
import { toast, Toaster } from 'react-hot-toast';
import { 
  Shield, 
  Search, 
  Brain, 
  Globe, 
  Mail, 
  Server, 
  Building, 
  DollarSign, 
  Plane, 
  Image, 
  Network, 
  Eye, 
  Zap, 
  ShieldCheck,
  BarChart3,
  Activity,
  Users,
  Clock,
  TrendingUp,
  Play,
  Pause,
  Settings,
  Home,
  FileSearch,
  Cpu,
  Layers3,
  Sparkles,
  ChevronRight,
  ExternalLink
} from 'lucide-react';

const ModernApp = () => {
  const [activeSection, setActiveSection] = useState('dashboard');
  const [selectedModule, setSelectedModule] = useState(null);
  const [apiStatus, setApiStatus] = useState('checking');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisQuery, setAnalysisQuery] = useState('');

  useEffect(() => {
    // Check API status
    fetch('http://localhost:8000/health')
      .then(() => {
        setApiStatus('online');
        toast.success('🟢 OSINT Suite Online', { duration: 3000 });
      })
      .catch(() => {
        setApiStatus('offline');
        toast.error('🔴 API Connection Failed', { duration: 3000 });
      });
  }, []);

  const modules = [
    {
      id: 'domain',
      name: 'Domain Intelligence',
      icon: Globe,
      description: 'Advanced DNS, WHOIS & subdomain reconnaissance',
      color: 'from-blue-500 to-cyan-500',
      bgGlow: 'shadow-blue-500/25',
      stats: { queries: 1247, success: 94 }
    },
    {
      id: 'email',
      name: 'Email Intelligence',
      icon: Mail,
      description: 'Email verification, breach analysis & patterns',
      color: 'from-emerald-500 to-teal-500',
      bgGlow: 'shadow-emerald-500/25',
      stats: { queries: 892, success: 89 }
    },
    {
      id: 'network',
      name: 'Network Analysis',
      icon: Server,
      description: 'IP geolocation, ASN lookup & infrastructure mapping',
      color: 'from-purple-500 to-violet-500',
      bgGlow: 'shadow-purple-500/25',
      stats: { queries: 634, success: 97 }
    },
    {
      id: 'company',
      name: 'Corporate Intel',
      icon: Building,
      description: 'Business intelligence & corporate reconnaissance',
      color: 'from-orange-500 to-red-500',
      bgGlow: 'shadow-orange-500/25',
      stats: { queries: 423, success: 91 }
    },
    {
      id: 'crypto',
      name: 'Blockchain Analysis',
      icon: DollarSign,
      description: 'Cryptocurrency tracking & wallet analysis',
      color: 'from-yellow-500 to-amber-500',
      bgGlow: 'shadow-yellow-500/25',
      stats: { queries: 289, success: 88 }
    },
    {
      id: 'flight',
      name: 'Aviation Intel',
      icon: Plane,
      description: 'Flight tracking, aircraft registration & patterns',
      color: 'from-indigo-500 to-blue-500',
      bgGlow: 'shadow-indigo-500/25',
      stats: { queries: 156, success: 95 }
    },
    {
      id: 'media',
      name: 'Media Forensics',
      icon: Image,
      description: 'Image metadata, reverse search & verification',
      color: 'from-pink-500 to-rose-500',
      bgGlow: 'shadow-pink-500/25',
      stats: { queries: 367, success: 92 }
    },
    {
      id: 'ai',
      name: 'AI Analysis Engine',
      icon: Brain,
      description: 'Machine learning powered intelligence analysis',
      color: 'from-violet-500 to-purple-500',
      bgGlow: 'shadow-violet-500/25',
      stats: { queries: 2341, success: 96 }
    }
  ];

  const stats = [
    { label: 'Total Investigations', value: '2,847', icon: FileSearch, change: '+12%' },
    { label: 'Success Rate', value: '94.2%', icon: TrendingUp, change: '+2.1%' },
    { label: 'Active Modules', value: '12', icon: Layers3, change: '100%' },
    { label: 'AI Queries', value: '15.7K', icon: Brain, change: '+34%' }
  ];

  const handleModuleClick = async (module) => {
    setSelectedModule(module.id);
    toast.loading(`Initializing ${module.name}...`, { duration: 2000 });
    
    // Simulate API call
    setTimeout(() => {
      toast.success(`${module.name} Ready`, { duration: 2000 });
    }, 1500);
  };

  const handleAnalysis = async () => {
    if (!analysisQuery.trim()) {
      toast.error('Please enter a query for analysis');
      return;
    }

    setIsAnalyzing(true);
    toast.loading('AI Analysis in progress...', { duration: 3000 });

    try {
      await new Promise(resolve => setTimeout(resolve, 3000));
      toast.success('Analysis completed successfully!');
      setAnalysisQuery('');
    } catch (error) {
      toast.error('Analysis failed. Please try again.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const sidebarItems = [
    { id: 'dashboard', name: 'Dashboard', icon: Home },
    { id: 'modules', name: 'OSINT Modules', icon: Layers3 },
    { id: 'ai-center', name: 'AI Analysis', icon: Brain },
    { id: 'geointel', name: 'Geo Intelligence', icon: Globe },
    { id: 'investigations', name: 'Investigations', icon: FileSearch },
    { id: 'settings', name: 'Settings', icon: Settings }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <Toaster 
        position="top-right"
        toastOptions={{
          style: {
            background: '#1e293b',
            color: '#fff',
            border: '1px solid #334155'
          }
        }}
      />
      
      <div className="flex">
        {/* Sidebar */}
        <motion.div 
          initial={{ x: -300, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          className="w-72 bg-slate-900/90 backdrop-blur-xl border-r border-slate-800 min-h-screen"
        >
          <div className="p-6">
            {/* Logo */}
            <motion.div 
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ delay: 0.2 }}
              className="flex items-center space-x-3 mb-8"
            >
              <div className="bg-gradient-to-r from-blue-500 to-purple-500 p-3 rounded-xl shadow-lg">
                <Shield className="w-7 h-7 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold bg-gradient-to-r from-white to-slate-300 bg-clip-text text-transparent">
                  OSINT Suite
                </h1>
                <p className="text-xs text-slate-400">Professional Intelligence Platform</p>
              </div>
            </motion.div>

            {/* Status Badge */}
            <motion.div 
              initial={{ y: 20, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: 0.3 }}
              className="mb-6"
            >
              <div className={`flex items-center space-x-2 px-3 py-2 rounded-lg ${
                apiStatus === 'online' 
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' 
                  : 'bg-red-500/20 text-red-400 border border-red-500/30'
              }`}>
                <Activity className="w-4 h-4" />
                <span className="text-sm font-medium">
                  {apiStatus === 'online' ? 'System Online' : 'System Offline'}
                </span>
              </div>
            </motion.div>

            {/* Navigation */}
            <nav className="space-y-2">
              {sidebarItems.map((item, index) => {
                const Icon = item.icon;
                return (
                  <motion.button
                    key={item.id}
                    initial={{ x: -50, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    transition={{ delay: 0.1 * index }}
                    onClick={() => setActiveSection(item.id)}
                    className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl text-left transition-all duration-300 group ${
                      activeSection === item.id
                        ? 'bg-gradient-to-r from-blue-500/20 to-purple-500/20 border border-blue-500/30 text-white shadow-lg'
                        : 'text-slate-400 hover:text-white hover:bg-slate-800/50 hover:translate-x-1'
                    }`}
                  >
                    <Icon className="w-5 h-5" />
                    <span className="font-medium">{item.name}</span>
                    <ChevronRight className={`w-4 h-4 ml-auto transition-transform duration-300 ${
                      activeSection === item.id ? 'rotate-90' : 'group-hover:translate-x-1'
                    }`} />
                  </motion.button>
                );
              })}
            </nav>
          </div>
        </motion.div>

        {/* Main Content */}
        <div className="flex-1 p-8">
          <div className="max-w-7xl mx-auto">
            <AnimatePresence mode="wait">
              {activeSection === 'dashboard' && (
                <motion.div
                  key="dashboard"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-8"
                >
                  {/* Header */}
                  <div className="flex justify-between items-center">
                    <div>
                      <h2 className="text-3xl font-bold bg-gradient-to-r from-white to-slate-300 bg-clip-text text-transparent">
                        Intelligence Dashboard
                      </h2>
                      <p className="text-slate-400 mt-1">Comprehensive OSINT operations center</p>
                    </div>
                    <motion.div 
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                      className="bg-gradient-to-r from-blue-500 to-purple-500 px-6 py-3 rounded-xl text-white font-medium cursor-pointer shadow-lg hover:shadow-xl transition-shadow"
                    >
                      <Play className="w-5 h-5 inline mr-2" />
                      Start Investigation
                    </motion.div>
                  </div>

                  {/* Stats Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    {stats.map((stat, index) => {
                      const Icon = stat.icon;
                      return (
                        <motion.div
                          key={stat.label}
                          initial={{ opacity: 0, y: 20 }}
                          animate={{ opacity: 1, y: 0 }}
                          transition={{ delay: 0.1 * index }}
                          whileHover={{ y: -5, scale: 1.02 }}
                          className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6 hover:border-blue-500/30 transition-all duration-300 shadow-xl"
                        >
                          <div className="flex items-center justify-between mb-4">
                            <div className="bg-gradient-to-r from-blue-500/20 to-purple-500/20 p-3 rounded-xl">
                              <Icon className="w-6 h-6 text-blue-400" />
                            </div>
                            <span className="text-emerald-400 text-sm font-medium">{stat.change}</span>
                          </div>
                          <div>
                            <p className="text-2xl font-bold text-white mb-1">{stat.value}</p>
                            <p className="text-slate-400 text-sm">{stat.label}</p>
                          </div>
                        </motion.div>
                      );
                    })}
                  </div>

                  {/* Quick Actions */}
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <motion.div
                      whileHover={{ scale: 1.02 }}
                      onClick={() => setActiveSection('modules')}
                      className="bg-gradient-to-br from-blue-500/10 to-cyan-500/10 border border-blue-500/20 rounded-2xl p-6 cursor-pointer hover:border-blue-500/40 transition-all duration-300 shadow-xl"
                    >
                      <Layers3 className="w-8 h-8 text-blue-400 mb-4" />
                      <h3 className="text-lg font-semibold text-white mb-2">Explore Modules</h3>
                      <p className="text-slate-400 text-sm mb-4">Access all 12 OSINT intelligence modules</p>
                      <div className="flex items-center text-blue-400 text-sm font-medium">
                        Browse Tools <ExternalLink className="w-4 h-4 ml-2" />
                      </div>
                    </motion.div>

                    <motion.div
                      whileHover={{ scale: 1.02 }}
                      onClick={() => setActiveSection('ai-center')}
                      className="bg-gradient-to-br from-purple-500/10 to-violet-500/10 border border-purple-500/20 rounded-2xl p-6 cursor-pointer hover:border-purple-500/40 transition-all duration-300 shadow-xl"
                    >
                      <Brain className="w-8 h-8 text-purple-400 mb-4" />
                      <h3 className="text-lg font-semibold text-white mb-2">AI Analysis</h3>
                      <p className="text-slate-400 text-sm mb-4">Advanced AI-powered intelligence analysis</p>
                      <div className="flex items-center text-purple-400 text-sm font-medium">
                        Start Analysis <ExternalLink className="w-4 h-4 ml-2" />
                      </div>
                    </motion.div>

                    <motion.div
                      whileHover={{ scale: 1.02 }}
                      onClick={() => setActiveSection('investigations')}
                      className="bg-gradient-to-br from-emerald-500/10 to-teal-500/10 border border-emerald-500/20 rounded-2xl p-6 cursor-pointer hover:border-emerald-500/40 transition-all duration-300 shadow-xl"
                    >
                      <FileSearch className="w-8 h-8 text-emerald-400 mb-4" />
                      <h3 className="text-lg font-semibold text-white mb-2">New Investigation</h3>
                      <p className="text-slate-400 text-sm mb-4">Create and manage investigation cases</p>
                      <div className="flex items-center text-emerald-400 text-sm font-medium">
                        Create Case <ExternalLink className="w-4 h-4 ml-2" />
                      </div>
                    </motion.div>
                  </div>
                </motion.div>
              )}

              {activeSection === 'modules' && (
                <motion.div
                  key="modules"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-8"
                >
                  <div>
                    <h2 className="text-3xl font-bold bg-gradient-to-r from-white to-slate-300 bg-clip-text text-transparent">
                      OSINT Intelligence Modules
                    </h2>
                    <p className="text-slate-400 mt-1">Professional-grade intelligence gathering tools</p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                    {modules.map((module, index) => {
                      const Icon = module.icon;
                      return (
                        <motion.div
                          key={module.id}
                          initial={{ opacity: 0, y: 20 }}
                          animate={{ opacity: 1, y: 0 }}
                          transition={{ delay: 0.1 * index }}
                          whileHover={{ y: -8, scale: 1.03 }}
                          whileTap={{ scale: 0.98 }}
                          onClick={() => handleModuleClick(module)}
                          className={`bg-gradient-to-br from-slate-800/40 to-slate-900/40 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6 cursor-pointer hover:border-blue-500/30 transition-all duration-500 shadow-xl hover:shadow-2xl ${module.bgGlow} ${
                            selectedModule === module.id ? 'ring-2 ring-blue-500/50 border-blue-500/50' : ''
                          }`}
                        >
                          <div className={`bg-gradient-to-r ${module.color} p-4 rounded-xl mb-4 shadow-lg`}>
                            <Icon className="w-8 h-8 text-white" />
                          </div>
                          
                          <h3 className="text-lg font-semibold text-white mb-2">{module.name}</h3>
                          <p className="text-slate-400 text-sm mb-4">{module.description}</p>
                          
                          <div className="flex justify-between items-center text-xs">
                            <span className="text-slate-500">{module.stats.queries} queries</span>
                            <span className="text-emerald-400">{module.stats.success}% success</span>
                          </div>
                          
                          {selectedModule === module.id && (
                            <motion.div
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              className="mt-4 text-center"
                            >
                              <span className="inline-flex items-center text-blue-400 text-sm font-medium">
                                <Sparkles className="w-4 h-4 mr-1" />
                                Module Active
                              </span>
                            </motion.div>
                          )}
                        </motion.div>
                      );
                    })}
                  </div>
                </motion.div>
              )}

              {activeSection === 'ai-center' && (
                <motion.div
                  key="ai-center"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-8"
                >
                  <div>
                    <h2 className="text-3xl font-bold bg-gradient-to-r from-white to-slate-300 bg-clip-text text-transparent">
                      AI Analysis Center
                    </h2>
                    <p className="text-slate-400 mt-1">Advanced artificial intelligence for OSINT analysis</p>
                  </div>

                  <div className="bg-gradient-to-br from-slate-800/40 to-slate-900/40 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-8 shadow-xl">
                    <div className="space-y-6">
                      <div>
                        <label className="block text-sm font-medium text-slate-300 mb-3">
                          Intelligence Query
                        </label>
                        <textarea
                          value={analysisQuery}
                          onChange={(e) => setAnalysisQuery(e.target.value)}
                          placeholder="Enter your OSINT query for AI-powered analysis..."
                          className="w-full h-32 bg-slate-900/50 border border-slate-600/50 rounded-xl p-4 text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 transition-all duration-300 backdrop-blur-sm"
                        />
                      </div>
                      
                      <motion.button
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        onClick={handleAnalysis}
                        disabled={isAnalyzing || !analysisQuery.trim()}
                        className="bg-gradient-to-r from-purple-500 to-violet-500 hover:from-purple-600 hover:to-violet-600 disabled:opacity-50 disabled:cursor-not-allowed px-8 py-4 rounded-xl font-medium text-white transition-all duration-300 shadow-lg hover:shadow-xl flex items-center space-x-2"
                      >
                        {isAnalyzing ? (
                          <>
                            <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                            <span>Analyzing...</span>
                          </>
                        ) : (
                          <>
                            <Brain className="w-5 h-5" />
                            <span>Start AI Analysis</span>
                          </>
                        )}
                      </motion.button>
                    </div>
                  </div>
                </motion.div>
              )}

              {activeSection === 'geointel' && (
                <motion.div
                  key="geointel"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-8"
                >
                  <div>
                    <h2 className="text-3xl font-bold bg-gradient-to-r from-white to-slate-300 bg-clip-text text-transparent">
                      Geospatial Intelligence
                    </h2>
                    <p className="text-slate-400 mt-1">Live infrastructure & flight route visualization (prototype)</p>
                  </div>
                  <div className="bg-gradient-to-br from-slate-800/40 to-slate-900/40 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6 shadow-xl">
                    <GeoMap />
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ModernApp;