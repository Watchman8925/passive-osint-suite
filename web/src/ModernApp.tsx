import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
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
  ExternalLink,
  Menu,
  X,
  Database,
  Target,
  Radar,
  AlertTriangle,
  CheckCircle,
  Loader2,
  Send,
  Download,
  Upload,
  Filter,
  Calendar,
  MapPin,
  User,
  Lock,
  Wifi,
  Smartphone,
  Monitor,
  HardDrive,
  Cloud,
  Code,
  BookOpen,
  Award,
  Briefcase,
  Camera,
  MessageSquare,
  Heart,
  Star,
  Zap as Lightning,
  RefreshCw,
  Plus,
  Minus,
  Maximize2,
  Minimize2
} from 'lucide-react';

// Get API URL from environment variable with fallback
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const ModernApp = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [apiStatus, setApiStatus] = useState('checking');
  const [isLoading, setIsLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedModule, setSelectedModule] = useState(null);

  useEffect(() => {
    // Check API status with proper error handling
    const checkHealth = async () => {
      try {
        const response = await fetch(`${API_URL}/api/health`, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
        });
        if (response.ok) {
          setApiStatus('online');
        } else {
          setApiStatus('offline');
        }
      } catch (error) {
        console.error('API health check failed:', error);
        setApiStatus('offline');
      }
    };

    checkHealth();
    // Re-check every 30 seconds
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const navigation = [
    { id: 'dashboard', name: 'Dashboard', icon: Home, color: 'text-blue-600' },
    { id: 'modules', name: 'OSINT Modules', icon: Layers3, color: 'text-purple-600' },
    { id: 'intelligence', name: 'Intelligence', icon: Target, color: 'text-green-600' },
    { id: 'analysis', name: 'Analysis', icon: Brain, color: 'text-yellow-600' },
    { id: 'investigations', name: 'Investigations', icon: FileSearch, color: 'text-red-600' },
    { id: 'reports', name: 'Reports', icon: BarChart3, color: 'text-indigo-600' },
    { id: 'settings', name: 'Settings', icon: Settings, color: 'text-gray-600' }
  ];

  const modules = [
    {
      id: 'domain',
      name: 'Domain Intelligence',
      icon: Globe,
      description: 'DNS, WHOIS & subdomain analysis',
      category: 'network',
      status: 'active',
      lastUsed: '2 hours ago'
    },
    {
      id: 'email',
      name: 'Email Intelligence',
      icon: Mail,
      description: 'Email verification & breach analysis',
      category: 'communication',
      status: 'active',
      lastUsed: '1 day ago'
    },
    {
      id: 'social_passive',
      name: 'Social Media Passive',
      icon: Users,
      description: 'Multi-platform profile monitoring',
      category: 'social',
      status: 'active',
      lastUsed: '30 mins ago'
    },
    {
      id: 'academic_passive',
      name: 'Academic Research',
      icon: BookOpen,
      description: 'Research paper & academic databases',
      category: 'research',
      status: 'active',
      lastUsed: '3 hours ago'
    },
    {
      id: 'patent_passive',
      name: 'Patent Intelligence',
      icon: Award,
      description: 'Global patent database search',
      category: 'research',
      status: 'active',
      lastUsed: '1 hour ago'
    },
    {
      id: 'gitlab_passive',
      name: 'GitLab Passive',
      icon: Code,
      description: 'Repository & user intelligence',
      category: 'code',
      status: 'active',
      lastUsed: '45 mins ago'
    },
    {
      id: 'bitbucket_passive',
      name: 'Bitbucket Passive',
      icon: Code,
      description: 'Repository & user intelligence',
      category: 'code',
      status: 'active',
      lastUsed: '2 hours ago'
    },
    {
      id: 'company',
      name: 'Corporate Intel',
      icon: Building,
      description: 'Business intelligence & analysis',
      category: 'business',
      status: 'active',
      lastUsed: '4 hours ago'
    }
  ];

  const stats = [
    { label: 'Active Investigations', value: '12', icon: Target, trend: '+2', color: 'text-blue-600' },
    { label: 'Data Points Collected', value: '45.2K', icon: Database, trend: '+12%', color: 'text-green-600' },
    { label: 'Success Rate', value: '94.8%', icon: CheckCircle, trend: '+1.2%', color: 'text-emerald-600' },
    { label: 'System Uptime', value: '99.9%', icon: Activity, trend: 'stable', color: 'text-purple-600' }
  ];

  const handleModuleRun = async (moduleId) => {
    setIsLoading(true);
    setSelectedModule(moduleId);

    // Simulate API call
    setTimeout(() => {
      setIsLoading(false);
      setSelectedModule(null);
    }, 2000);
  };

  const handleSearch = () => {
    if (!searchQuery.trim()) return;
    setIsLoading(true);
    // Simulate search
    setTimeout(() => setIsLoading(false), 1500);
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            {/* Logo and Title */}
            <div className="flex items-center space-x-4">
              <div className="bg-gradient-to-r from-blue-600 to-purple-600 p-2 rounded-lg shadow-md">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">OSINT Suite</h1>
                <p className="text-sm text-gray-500">Professional Intelligence Platform</p>
              </div>
            </div>

            {/* Search Bar */}
            <div className="flex-1 max-w-md mx-8">
              <div className="relative">
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search intelligence data..."
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white"
                />
                <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                <button
                  onClick={handleSearch}
                  className="absolute right-2 top-1 bg-blue-600 text-white px-3 py-1 rounded text-sm hover:bg-blue-700 transition-colors"
                >
                  Search
                </button>
              </div>
            </div>

            {/* Status and Actions */}
            <div className="flex items-center space-x-4">
              <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm ${
                apiStatus === 'online'
                  ? 'bg-green-100 text-green-700 border border-green-200'
                  : 'bg-red-100 text-red-700 border border-red-200'
              }`}>
                <div className={`w-2 h-2 rounded-full ${apiStatus === 'online' ? 'bg-green-500' : 'bg-red-500'}`}></div>
                <span className="font-medium">{apiStatus === 'online' ? 'API Online' : 'API Offline'}</span>
              </div>

              <button className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors">
                <Settings className="w-5 h-5" />
              </button>

              <button
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors lg:hidden"
              >
                <Menu className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <aside className={`fixed inset-y-0 left-0 z-50 w-64 bg-white border-r border-gray-200 shadow-lg transform ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        } transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:inset-0`}>
          <div className="flex flex-col h-full pt-16 lg:pt-0">
            {/* Navigation */}
            <nav className="flex-1 px-4 py-6">
              <div className="space-y-2">
                {navigation.map((item) => {
                  const Icon = item.icon;
                  return (
                    <button
                      key={item.id}
                      onClick={() => {
                        setActiveTab(item.id);
                        setSidebarOpen(false);
                      }}
                      className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-left transition-all duration-200 ${
                        activeTab === item.id
                          ? 'bg-blue-50 text-blue-700 border-r-4 border-blue-600 shadow-sm'
                          : 'text-gray-700 hover:bg-gray-50 hover:text-gray-900'
                      }`}
                    >
                      <Icon className={`w-5 h-5 ${activeTab === item.id ? item.color : 'text-gray-500'}`} />
                      <span className="font-medium">{item.name}</span>
                      {activeTab === item.id && (
                        <ChevronRight className="w-4 h-4 ml-auto text-blue-600" />
                      )}
                    </button>
                  );
                })}
              </div>
            </nav>

            {/* Quick Stats */}
            <div className="px-4 pb-6">
              <div className="bg-gradient-to-r from-blue-50 to-purple-50 rounded-lg p-4 border border-gray-200">
                <h3 className="text-sm font-semibold text-gray-900 mb-3">System Status</h3>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-gray-600">Active Modules</span>
                    <span className="font-medium text-gray-900">18</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Data Sources</span>
                    <span className="font-medium text-gray-900">50+</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Queries Today</span>
                    <span className="font-medium text-gray-900">247</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </aside>

        {/* Overlay for mobile */}
        {sidebarOpen && (
          <div
            className="fixed inset-0 z-40 bg-black/50 lg:hidden"
            onClick={() => setSidebarOpen(false)}
          />
        )}

        {/* Main Content */}
        <main className="flex-1 lg:ml-0">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <AnimatePresence mode="wait">
              {activeTab === 'dashboard' && (
                <motion.div
                  key="dashboard"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-8"
                >
                  {/* Welcome Section */}
                  <div className="bg-gradient-to-r from-blue-600 to-purple-600 rounded-xl p-8 text-white">
                    <div className="flex items-center justify-between">
                      <div>
                        <h2 className="text-3xl font-bold mb-2">Welcome to OSINT Suite</h2>
                        <p className="text-blue-100 text-lg">Professional intelligence gathering and analysis platform</p>
                      </div>
                      <div className="hidden md:block">
                        <Shield className="w-16 h-16 text-blue-200" />
                      </div>
                    </div>
                  </div>

                  {/* Stats Cards */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    {stats.map((stat, index) => {
                      const Icon = stat.icon;
                      return (
                        <motion.div
                          key={stat.label}
                          initial={{ opacity: 0, y: 20 }}
                          animate={{ opacity: 1, y: 0 }}
                          transition={{ delay: 0.1 * index }}
                          className="bg-white rounded-xl p-6 border border-gray-200 shadow-sm hover:shadow-md transition-shadow"
                        >
                          <div className="flex items-center justify-between mb-4">
                            <div className="bg-blue-50 p-3 rounded-lg">
                              <Icon className="w-6 h-6 text-blue-600" />
                            </div>
                            <span className={`text-sm font-medium ${stat.color}`}>{stat.trend}</span>
                          </div>
                          <div>
                            <p className="text-2xl font-bold text-gray-900 mb-1">{stat.value}</p>
                            <p className="text-gray-600 text-sm">{stat.label}</p>
                          </div>
                        </motion.div>
                      );
                    })}
                  </div>

                  {/* Recent Activity & Quick Actions */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    {/* Recent Activity */}
                    <div className="bg-white rounded-xl p-6 border border-gray-200 shadow-sm">
                      <div className="flex items-center justify-between mb-6">
                        <h3 className="text-lg font-semibold text-gray-900 flex items-center">
                          <Activity className="w-5 h-5 mr-2 text-blue-600" />
                          Recent Activity
                        </h3>
                        <button className="text-blue-600 hover:text-blue-700 text-sm font-medium">
                          View All
                        </button>
                      </div>
                      <div className="space-y-4">
                        {[
                          { action: 'Domain scan completed', target: 'example.com', time: '2 mins ago', status: 'success' },
                          { action: 'Social media analysis', target: 'john_doe', time: '15 mins ago', status: 'success' },
                          { action: 'Email verification', target: 'user@domain.com', time: '1 hour ago', status: 'warning' },
                          { action: 'Patent search', target: 'AI algorithms', time: '2 hours ago', status: 'success' }
                        ].map((activity, index) => (
                          <div key={index} className="flex items-center space-x-4 p-4 bg-gray-50 rounded-lg">
                            <div className={`w-3 h-3 rounded-full ${
                              activity.status === 'success' ? 'bg-green-500' :
                              activity.status === 'warning' ? 'bg-yellow-500' : 'bg-red-500'
                            }`}></div>
                            <div className="flex-1">
                              <p className="text-sm font-medium text-gray-900">{activity.action}</p>
                              <p className="text-xs text-gray-600">{activity.target}</p>
                            </div>
                            <span className="text-xs text-gray-500">{activity.time}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Quick Actions */}
                    <div className="bg-white rounded-xl p-6 border border-gray-200 shadow-sm">
                      <div className="flex items-center justify-between mb-6">
                        <h3 className="text-lg font-semibold text-gray-900 flex items-center">
                          <Lightning className="w-5 h-5 mr-2 text-purple-600" />
                          Quick Actions
                        </h3>
                        <button className="text-purple-600 hover:text-purple-700 text-sm font-medium">
                          Customize
                        </button>
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        {[
                          { name: 'Domain Lookup', icon: Globe, color: 'bg-blue-50 text-blue-700 hover:bg-blue-100' },
                          { name: 'Email Check', icon: Mail, color: 'bg-green-50 text-green-700 hover:bg-green-100' },
                          { name: 'Social Scan', icon: Users, color: 'bg-purple-50 text-purple-700 hover:bg-purple-100' },
                          { name: 'IP Analysis', icon: Server, color: 'bg-orange-50 text-orange-700 hover:bg-orange-100' }
                        ].map((action, index) => {
                          const Icon = action.icon;
                          return (
                            <button
                              key={index}
                              className={`p-4 rounded-lg border border-gray-200 transition-colors ${action.color}`}
                            >
                              <Icon className="w-6 h-6 mx-auto mb-2" />
                              <span className="text-sm font-medium">{action.name}</span>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {activeTab === 'modules' && (
                <motion.div
                  key="modules"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-8"
                >
                  {/* Header */}
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
                    <div>
                      <h2 className="text-3xl font-bold text-gray-900">OSINT Modules</h2>
                      <p className="text-gray-600 mt-1">Choose and run intelligence gathering tools</p>
                    </div>
                    <div className="mt-4 sm:mt-0 flex space-x-3">
                      <select className="bg-white border border-gray-300 text-gray-700 px-4 py-2 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                        <option>All Categories</option>
                        <option>Network</option>
                        <option>Social</option>
                        <option>Research</option>
                        <option>Code</option>
                        <option>Business</option>
                      </select>
                      <button className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2">
                        <Filter className="w-4 h-4" />
                        <span>Filter</span>
                      </button>
                    </div>
                  </div>

                  {/* Modules Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                    {modules.map((module, index) => {
                      const Icon = module.icon;
                      return (
                        <motion.div
                          key={module.id}
                          initial={{ opacity: 0, y: 20 }}
                          animate={{ opacity: 1, y: 0 }}
                          transition={{ delay: 0.1 * index }}
                          className="bg-white rounded-xl p-6 border border-gray-200 shadow-sm hover:shadow-lg transition-all duration-200 hover:border-blue-300"
                        >
                          <div className="flex items-start justify-between mb-4">
                            <div className="bg-blue-50 p-3 rounded-lg">
                              <Icon className="w-6 h-6 text-blue-600" />
                            </div>
                            <div className={`px-2 py-1 rounded-full text-xs font-medium ${
                              module.status === 'active'
                                ? 'bg-green-100 text-green-700'
                                : 'bg-gray-100 text-gray-700'
                            }`}>
                              {module.status}
                            </div>
                          </div>

                          <h3 className="text-lg font-semibold text-gray-900 mb-2">{module.name}</h3>
                          <p className="text-gray-600 text-sm mb-4">{module.description}</p>

                          <div className="flex items-center justify-between text-xs text-gray-500 mb-4">
                            <span className="bg-gray-100 px-2 py-1 rounded">{module.category}</span>
                            <span>{module.lastUsed}</span>
                          </div>

                          <button
                            onClick={() => handleModuleRun(module.id)}
                            disabled={isLoading && selectedModule === module.id}
                            className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center space-x-2"
                          >
                            {isLoading && selectedModule === module.id ? (
                              <>
                                <Loader2 className="w-4 h-4 animate-spin" />
                                <span>Running...</span>
                              </>
                            ) : (
                              <>
                                <Play className="w-4 h-4" />
                                <span>Run Module</span>
                              </>
                            )}
                          </button>
                        </motion.div>
                      );
                    })}
                  </div>
                </motion.div>
              )}

              {activeTab === 'intelligence' && (
                <motion.div
                  key="intelligence"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-8"
                >
                  <div>
                    <h2 className="text-3xl font-bold text-gray-900">Intelligence Center</h2>
                    <p className="text-gray-600 mt-1">Real-time intelligence gathering and monitoring</p>
                  </div>

                  {/* Intelligence Input Form */}
                  <div className="bg-white rounded-xl p-8 border border-gray-200 shadow-sm">
                    <div className="mb-6">
                      <h3 className="text-xl font-semibold text-gray-900 mb-2">New Intelligence Query</h3>
                      <p className="text-gray-600">Configure your intelligence gathering parameters</p>
                    </div>

                    <div className="space-y-6">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Target Type
                          </label>
                          <select className="w-full border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white">
                            <option>Domain</option>
                            <option>Email</option>
                            <option>Username</option>
                            <option>IP Address</option>
                            <option>Company</option>
                            <option>Phone Number</option>
                          </select>
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Priority Level
                          </label>
                          <select className="w-full border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white">
                            <option>Low</option>
                            <option>Medium</option>
                            <option>High</option>
                            <option>Critical</option>
                          </select>
                        </div>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                          Query Details
                        </label>
                        <textarea
                          rows={4}
                          placeholder="Enter your intelligence query details..."
                          className="w-full border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white"
                        />
                      </div>

                      <div className="flex flex-wrap gap-4">
                        <label className="flex items-center space-x-2">
                          <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" />
                          <span className="text-sm text-gray-700">Include passive sources</span>
                        </label>
                        <label className="flex items-center space-x-2">
                          <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" />
                          <span className="text-sm text-gray-700">Real-time monitoring</span>
                        </label>
                        <label className="flex items-center space-x-2">
                          <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" />
                          <span className="text-sm text-gray-700">Advanced analysis</span>
                        </label>
                      </div>

                      <div className="flex space-x-4">
                        <button className="bg-blue-600 text-white px-8 py-3 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2">
                          <Search className="w-4 h-4" />
                          <span>Start Intelligence Gathering</span>
                        </button>
                        <button className="bg-white border border-gray-300 text-gray-700 px-6 py-3 rounded-lg hover:bg-gray-50 transition-colors">
                          Save Query
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Active Intelligence Operations */}
                  <div className="bg-white rounded-xl p-6 border border-gray-200 shadow-sm">
                    <div className="flex items-center justify-between mb-6">
                      <h3 className="text-lg font-semibold text-gray-900">Active Operations</h3>
                      <button className="text-blue-600 hover:text-blue-700 text-sm font-medium">
                        View All
                      </button>
                    </div>
                    <div className="space-y-4">
                      {[
                        { id: 'op-001', target: 'example.com', type: 'Domain Analysis', progress: 75, status: 'running' },
                        { id: 'op-002', target: 'john.doe@email.com', type: 'Email Intelligence', progress: 45, status: 'running' },
                        { id: 'op-003', target: 'techcorp.com', type: 'Corporate Intel', progress: 100, status: 'completed' }
                      ].map((op) => (
                        <div key={op.id} className="flex items-center space-x-4 p-4 bg-gray-50 rounded-lg">
                          <div className={`w-3 h-3 rounded-full ${
                            op.status === 'running' ? 'bg-blue-500' : 'bg-green-500'
                          }`}></div>
                          <div className="flex-1">
                            <div className="flex items-center justify-between mb-1">
                              <span className="font-medium text-gray-900">{op.type}</span>
                              <span className="text-sm text-gray-600">{op.progress}%</span>
                            </div>
                            <div className="w-full bg-gray-200 rounded-full h-2 mb-2">
                              <div
                                className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                                style={{ width: `${op.progress}%` }}
                              ></div>
                            </div>
                            <span className="text-sm text-gray-600">{op.target}</span>
                          </div>
                          <button className="text-gray-500 hover:text-gray-700">
                            <X className="w-4 h-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                </motion.div>
              )}

              {activeTab === 'analysis' && (
                <motion.div
                  key="analysis"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-8"
                >
                  <div>
                    <h2 className="text-3xl font-bold text-gray-900">AI Analysis Center</h2>
                    <p className="text-gray-600 mt-1">Advanced AI-powered intelligence analysis</p>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    {/* Analysis Input */}
                    <div className="bg-white rounded-xl p-8 border border-gray-200 shadow-sm">
                      <div className="mb-6">
                        <h3 className="text-xl font-semibold text-gray-900 mb-2">Intelligence Analysis</h3>
                        <p className="text-gray-600">Upload data for AI-powered analysis</p>
                      </div>

                      <div className="space-y-6">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Analysis Type
                          </label>
                          <select className="w-full border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white">
                            <option>Pattern Recognition</option>
                            <option>Risk Assessment</option>
                            <option>Correlation Analysis</option>
                            <option>Threat Intelligence</option>
                            <option>Behavioral Analysis</option>
                          </select>
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Data Input
                          </label>
                          <textarea
                            rows={6}
                            placeholder="Paste intelligence data for analysis..."
                            className="w-full border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white"
                          />
                        </div>

                        <div className="flex space-x-4">
                          <button className="bg-purple-600 text-white px-8 py-3 rounded-lg hover:bg-purple-700 transition-colors flex items-center space-x-2">
                            <Brain className="w-4 h-4" />
                            <span>Analyze</span>
                          </button>
                          <button className="bg-white border border-gray-300 text-gray-700 px-6 py-3 rounded-lg hover:bg-gray-50 transition-colors flex items-center space-x-2">
                            <Upload className="w-4 h-4" />
                            <span>Upload File</span>
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Analysis Results */}
                    <div className="bg-white rounded-xl p-8 border border-gray-200 shadow-sm">
                      <div className="mb-6">
                        <h3 className="text-xl font-semibold text-gray-900 mb-2">Analysis Results</h3>
                        <p className="text-gray-600">AI-generated insights and findings</p>
                      </div>

                      <div className="space-y-6">
                        <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
                          <div className="flex items-center space-x-2 mb-3">
                            <CheckCircle className="w-5 h-5 text-green-600" />
                            <span className="font-medium text-green-800">High Confidence Match</span>
                          </div>
                          <p className="text-sm text-green-700">
                            Pattern detected: Social engineering indicators present in communication patterns.
                          </p>
                        </div>

                        <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                          <div className="flex items-center space-x-2 mb-3">
                            <AlertTriangle className="w-5 h-5 text-yellow-600" />
                            <span className="font-medium text-yellow-800">Medium Risk Detected</span>
                          </div>
                          <p className="text-sm text-yellow-700">
                            Anomalous activity detected in network traffic patterns.
                          </p>
                        </div>

                        <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg">
                          <div className="flex items-center space-x-2 mb-3">
                            <Radar className="w-5 h-5 text-blue-600" />
                            <span className="font-medium text-blue-800">Intelligence Insight</span>
                          </div>
                          <p className="text-sm text-blue-700">
                            Cross-referenced data shows connections to known threat actors.
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {activeTab === 'investigations' && (
                <motion.div
                  key="investigations"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-8"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
                    <div>
                      <h2 className="text-3xl font-bold text-gray-900">Investigations</h2>
                      <p className="text-gray-600 mt-1">Manage and track intelligence investigations</p>
                    </div>
                    <button className="mt-4 sm:mt-0 bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2">
                      <Plus className="w-4 h-4" />
                      <span>New Investigation</span>
                    </button>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                    {/* Investigation Stats */}
                    <div className="bg-white rounded-xl p-6 border border-gray-200 shadow-sm">
                      <h3 className="text-lg font-semibold text-gray-900 mb-6">Investigation Stats</h3>
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <span className="text-gray-600">Active Cases</span>
                          <span className="font-bold text-gray-900">8</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-gray-600">Completed</span>
                          <span className="font-bold text-green-600">24</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-gray-600">High Priority</span>
                          <span className="font-bold text-red-600">3</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-gray-600">This Month</span>
                          <span className="font-bold text-blue-600">12</span>
                        </div>
                      </div>
                    </div>

                    {/* Recent Investigations */}
                    <div className="lg:col-span-2 bg-white rounded-xl p-6 border border-gray-200 shadow-sm">
                      <h3 className="text-lg font-semibold text-gray-900 mb-6">Recent Investigations</h3>
                      <div className="space-y-4">
                        {[
                          { id: 'INV-2025-001', title: 'Corporate Espionage Investigation', status: 'active', priority: 'high', progress: 75 },
                          { id: 'INV-2025-002', title: 'Social Media Harassment Case', status: 'active', priority: 'medium', progress: 45 },
                          { id: 'INV-2025-003', title: 'Financial Fraud Analysis', status: 'completed', priority: 'high', progress: 100 },
                          { id: 'INV-2025-004', title: 'IP Theft Investigation', status: 'active', priority: 'medium', progress: 30 }
                        ].map((inv) => (
                          <div key={inv.id} className="flex items-center space-x-4 p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                            <div className={`w-3 h-3 rounded-full ${
                              inv.status === 'active' ? 'bg-blue-500' : 'bg-green-500'
                            }`}></div>
                            <div className="flex-1">
                              <div className="flex items-center justify-between mb-1">
                                <span className="font-medium text-gray-900">{inv.title}</span>
                                <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                                  inv.priority === 'high' ? 'bg-red-100 text-red-700' :
                                  inv.priority === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                                  'bg-green-100 text-green-700'
                                }`}>
                                  {inv.priority}
                                </span>
                              </div>
                              <div className="flex items-center justify-between text-sm text-gray-600">
                                <span>{inv.id}</span>
                                <span>{inv.progress}% complete</span>
                              </div>
                              <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
                                <div
                                  className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                                  style={{ width: `${inv.progress}%` }}
                                ></div>
                              </div>
                            </div>
                            <button className="text-gray-500 hover:text-gray-700">
                              <ChevronRight className="w-5 h-5" />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {activeTab === 'reports' && (
                <motion.div
                  key="reports"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-8"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
                    <div>
                      <h2 className="text-3xl font-bold text-gray-900">Reports & Analytics</h2>
                      <p className="text-gray-600 mt-1">Generate and view intelligence reports</p>
                    </div>
                    <div className="mt-4 sm:mt-0 flex space-x-3">
                      <button className="bg-white border border-gray-300 text-gray-700 px-4 py-2 rounded-lg hover:bg-gray-50 transition-colors flex items-center space-x-2">
                        <Download className="w-4 h-4" />
                        <span>Export All</span>
                      </button>
                      <button className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2">
                        <Plus className="w-4 h-4" />
                        <span>Generate Report</span>
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    {/* Report Generation */}
                    <div className="bg-white rounded-xl p-8 border border-gray-200 shadow-sm">
                      <div className="mb-6">
                        <h3 className="text-xl font-semibold text-gray-900 mb-2">Generate New Report</h3>
                        <p className="text-gray-600">Create comprehensive intelligence reports</p>
                      </div>

                      <div className="space-y-6">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Report Type
                          </label>
                          <select className="w-full border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white">
                            <option>Executive Summary</option>
                            <option>Technical Analysis</option>
                            <option>Threat Assessment</option>
                            <option>Investigation Timeline</option>
                            <option>Data Analytics</option>
                          </select>
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Date Range
                          </label>
                          <div className="grid grid-cols-2 gap-4">
                            <input
                              type="date"
                              className="border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white"
                            />
                            <input
                              type="date"
                              className="border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white"
                            />
                          </div>
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-4">
                            Include Data Sources
                          </label>
                          <div className="space-y-3">
                            {['Domain Intelligence', 'Social Media', 'Email Analysis', 'Network Data', 'Academic Research'].map((source) => (
                              <label key={source} className="flex items-center space-x-3">
                                <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" />
                                <span className="text-sm text-gray-700">{source}</span>
                              </label>
                            ))}
                          </div>
                        </div>

                        <button className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center space-x-2">
                          <FileSearch className="w-4 h-4" />
                          <span>Generate Report</span>
                        </button>
                      </div>
                    </div>

                    {/* Recent Reports */}
                    <div className="bg-white rounded-xl p-8 border border-gray-200 shadow-sm">
                      <div className="mb-6">
                        <h3 className="text-xl font-semibold text-gray-900 mb-2">Recent Reports</h3>
                        <p className="text-gray-600">Access your generated intelligence reports</p>
                      </div>

                      <div className="space-y-4">
                        {[
                          { title: 'Monthly Intelligence Summary', date: '2025-09-15', type: 'Executive', size: '2.4 MB' },
                          { title: 'Threat Actor Analysis', date: '2025-09-12', type: 'Technical', size: '1.8 MB' },
                          { title: 'Network Security Assessment', date: '2025-09-10', type: 'Assessment', size: '3.1 MB' },
                          { title: 'Social Media Monitoring Report', date: '2025-09-08', type: 'Analytics', size: '956 KB' }
                        ].map((report, index) => (
                          <div key={report.title + index} className="flex items-center space-x-4 p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                            <div className="bg-blue-50 p-3 rounded-lg">
                              <BarChart3 className="w-5 h-5 text-blue-600" />
                            </div>
                            <div className="flex-1">
                              <h4 className="font-medium text-gray-900">{report.title}</h4>
                              <div className="flex items-center space-x-4 text-sm text-gray-600 mt-1">
                                <span>{report.date}</span>
                                <span>{report.type}</span>
                                <span>{report.size}</span>
                              </div>
                            </div>
                            <button className="text-gray-500 hover:text-gray-700">
                              <Download className="w-4 h-4" />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {activeTab === 'settings' && (
                <motion.div
                  key="settings"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-8"
                >
                  <div>
                    <h2 className="text-3xl font-bold text-gray-900">Settings</h2>
                    <p className="text-gray-600 mt-1">Configure your OSINT Suite preferences</p>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    {/* System Settings */}
                    <div className="bg-white rounded-xl p-8 border border-gray-200 shadow-sm">
                      <div className="mb-6">
                        <h3 className="text-xl font-semibold text-gray-900 mb-2">System Configuration</h3>
                        <p className="text-gray-600">Manage system-wide settings and preferences</p>
                      </div>

                      <div className="space-y-6">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Max Concurrent Operations
                          </label>
                          <input
                            type="number"
                            defaultValue="5"
                            className="w-full border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white"
                          />
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Data Retention (days)
                          </label>
                          <input
                            type="number"
                            defaultValue="90"
                            className="w-full border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white"
                          />
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Report Storage Path
                          </label>
                          <input
                            type="text"
                            defaultValue="/opt/osint/reports"
                            className="w-full border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white"
                          />
                        </div>

                        <div className="flex items-center justify-between">
                          <span className="text-gray-700">Auto-save investigations</span>
                          <label className="relative inline-flex items-center cursor-pointer">
                            <input type="checkbox" className="sr-only peer" defaultChecked />
                            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                          </label>
                        </div>
                      </div>
                    </div>

                    {/* API Configuration */}
                    <div className="bg-white rounded-xl p-8 border border-gray-200 shadow-sm">
                      <div className="mb-6">
                        <h3 className="text-xl font-semibold text-gray-900 mb-2">API Configuration</h3>
                        <p className="text-gray-600">Manage external API keys and integrations</p>
                      </div>

                      <div className="space-y-4">
                        {[
                          { name: 'Shodan API', status: 'configured', lastUsed: '2 hours ago' },
                          { name: 'Hunter.io API', status: 'configured', lastUsed: '1 day ago' },
                          { name: 'OpenAI API', status: 'configured', lastUsed: '30 mins ago' },
                          { name: 'VirusTotal API', status: 'not_configured', lastUsed: 'never' }
                        ].map((api, index) => (
                          <div key={index} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                            <div>
                              <span className="font-medium text-gray-900">{api.name}</span>
                              <p className="text-sm text-gray-600">{api.lastUsed}</p>
                            </div>
                            <div className="flex items-center space-x-2">
                              <div className={`w-2 h-2 rounded-full ${
                                api.status === 'configured' ? 'bg-green-500' : 'bg-red-500'
                              }`}></div>
                              <button className="text-blue-600 hover:text-blue-700 text-sm font-medium">
                                {api.status === 'configured' ? 'Update' : 'Configure'}
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </main>
      </div>
    </div>
  );
};

export default ModernApp;
