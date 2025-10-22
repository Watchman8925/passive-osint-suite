import React, { useCallback, useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Search, Brain, Globe, Mail, Server, Building, DollarSign, Plane, Image, Network, Eye, Zap, ShieldCheck, ChartBar as BarChart3, Activity, Users, Clock, TrendingUp, Play, Pause, Settings, Hop as Home, FileSearch, Cpu, Layers as Layers3, Sparkles, ChevronRight, ExternalLink, Menu, X, Database, Target, Radar, TriangleAlert as AlertTriangle, CircleCheck as CheckCircle, Loader as Loader2, Send, Download, Upload, ListFilter as Filter, Calendar, MapPin, User, Lock, Wifi, Smartphone, Monitor, HardDrive, Cloud, Code, BookOpen, Award, Briefcase, Camera, MessageSquare, Heart, Star, Zap as Lightning, RefreshCw, Plus, Minus, Maximize2, Minimize2, LogIn, LogOut } from 'lucide-react';
import { Card } from './components/ui/Card';
import { ChatInterface } from './components/chat/ChatInterface';
import { useSelectedInvestigation } from './contexts/SelectedInvestigationContext';
import { LoginModal } from './components/auth/LoginModal';
import { SettingsModal } from './components/settings/SettingsModal';
import { DomainInvestigationModal } from './components/modules/DomainInvestigationModal';
import { useAuth } from './contexts/AuthContext';
import { useVisibilityPolling } from './hooks/useVisibilityPolling';

// Get API URL from environment variable with fallback
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const ModernApp = () => {
  const { selectedId: selectedInvestigationId } = useSelectedInvestigation();
  const { token, user, setSession, clearSession } = useAuth();
  const [activeTab, setActiveTab] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [apiStatus, setApiStatus] = useState<'checking' | 'online' | 'offline' | 'unauthorized'>('checking');
  const [isLoading, setIsLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedModule, setSelectedModule] = useState(null);
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);
  const [isSettingsModalOpen, setIsSettingsModalOpen] = useState(false);
  const [isDomainModalOpen, setIsDomainModalOpen] = useState(false);
  const checkHealth = useCallback(async () => {
    if (!token) {
      setApiStatus('unauthorized');
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/health`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });

      if (response.status === 401) {
        setApiStatus('unauthorized');
        return;
      }

      setApiStatus(response.ok ? 'online' : 'offline');
    } catch (error) {
      console.error('API health check failed:', error);
      setApiStatus('offline');
    }
  }, [token]);

  useEffect(() => {
    if (token) {
      setApiStatus('checking');
      void checkHealth();
    } else {
      setApiStatus('unauthorized');
    }
  }, [token, checkHealth]);

  useVisibilityPolling(checkHealth, { intervalMs: 30000, idleMs: 120000, immediate: true });

  const statusLabel =
    apiStatus === 'online'
      ? 'API Online'
      : apiStatus === 'unauthorized'
        ? 'Sign in required'
        : apiStatus === 'offline'
          ? 'API Offline'
          : 'Checking…';

  const statusTextClass =
    apiStatus === 'online'
      ? 'text-[var(--accent-seafoam)]'
      : apiStatus === 'unauthorized'
        ? 'text-[var(--accent-gold)]'
        : 'text-[var(--accent-silver)]';

  const statusDotClass =
    apiStatus === 'online'
      ? 'bg-[var(--accent-seafoam)]'
      : apiStatus === 'unauthorized'
        ? 'bg-[var(--accent-gold)]'
        : 'bg-[var(--accent-silver)]';

  const navigation = [
    { id: 'dashboard', name: 'Dashboard', icon: Home, color: 'text-[var(--accent-blue)]' },
    { id: 'modules', name: 'OSINT Modules', icon: Layers3, color: 'text-[var(--accent-seafoam)]' },
    { id: 'intelligence', name: 'Intelligence', icon: Target, color: 'text-[var(--accent-gold)]' },
    { id: 'analysis', name: 'Analysis', icon: Brain, color: 'text-[var(--accent-magenta)]' },
    { id: 'investigations', name: 'Investigations', icon: FileSearch, color: 'text-[var(--accent-silver)]' },
    { id: 'assistant', name: 'AI Assistant', icon: MessageSquare, color: 'text-[var(--accent-seafoam)]' },
    { id: 'reports', name: 'Reports', icon: BarChart3, color: 'text-[var(--accent-gold)]' },
    { id: 'settings', name: 'Settings', icon: Settings, color: 'text-[var(--accent-silver)]' }
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
    { label: 'Active Investigations', value: '12', icon: Target, trend: '+2', color: 'text-[var(--accent-blue)]' },
    { label: 'Data Points Collected', value: '45.2K', icon: Database, trend: '+12%', color: 'text-[var(--accent-seafoam)]' },
    { label: 'Success Rate', value: '94.8%', icon: CheckCircle, trend: '+1.2%', color: 'text-[var(--accent-gold)]' },
    { label: 'System Uptime', value: '99.9%', icon: Activity, trend: 'stable', color: 'text-[var(--accent-silver)]' }
  ];

  const handleModuleRun = async (moduleId) => {
    // Open specific modal for domain module
    if (moduleId === 'domain') {
      setIsDomainModalOpen(true);
      return;
    }

    setIsLoading(true);
    setSelectedModule(moduleId);

    if (!token) {
      alert('Please log in to run modules.');
      setIsLoading(false);
      setSelectedModule(null);
      setIsLoginModalOpen(true);
      return;
    }

    try {
      // Map frontend module IDs to backend module names
      const moduleNameMap: Record<string, string> = {
        'email': 'email_intel',
        'social_passive': 'social_media_footprint',
        'ip': 'ip_intel',
        'company': 'company_intel',
        'crypto': 'crypto_intel',
        'flight': 'flight_intel',
        'web_scraper': 'web_scraper',
        'github': 'github_search',
        'wayback': 'wayback_machine',
        'social': 'comprehensive_social_passive',
        'darkweb': 'darkweb_intel',
        'malware': 'malware_intel',
        'financial': 'financial_intel',
        'iot': 'iot_intel',
        'network': 'network_analysis',
        'dns': 'dns_intelligence',
        'certificate': 'certificate_transparency',
        'whois': 'whois_history',
        'breaches': 'public_breach_search',
        'patent': 'patent_passive',
        'geospatial': 'geospatial_intel',
      };

      const moduleName = moduleNameMap[moduleId] || moduleId;

      const response = await fetch(`${API_URL}/api/modules/execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          module_name: moduleName,
          parameters: {}
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Module execution failed' }));
        throw new Error(errorData.detail || 'Failed to execute module');
      }

      const data = await response.json();
      
      if (data.status === 'success') {
        // TODO: Display results in a modal or results panel
        console.log('Module execution result:', data.result);
        alert(`Module ${moduleName} executed successfully! Check console for results.`);
      } else {
        throw new Error(data.error || 'Module execution failed');
      }
    } catch (err: any) {
      console.error('Module execution error:', err);
      alert(`Error: ${err.message || 'Failed to execute module. Please try again.'}`);
    } finally {
      setIsLoading(false);
      setSelectedModule(null);
    }
  };

  const handleSearch = () => {
    if (!searchQuery.trim()) return;
    setIsLoading(true);
    // Simulate search
    setTimeout(() => setIsLoading(false), 1500);
  };

  const handleLoginSuccess = (userData: any, nextToken: string, options?: { ttlMs?: number }) => {
    setSession(userData, nextToken, options);
  };

  const handleLogout = () => {
    clearSession();
  };

  return (
    <div className="min-h-screen text-[var(--text-primary)]">
      {/* Header */}
      <header className="glass border-b border-[var(--glass-border)]/80 bg-[var(--glass-elevated)] shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            {/* Logo and Title */}
            <div className="flex items-center space-x-4">
              <div className="p-2 rounded-xl shadow-[0_0_25px_rgba(56,189,248,0.4)] bg-gradient-to-br from-[var(--accent-blue)] via-[var(--accent-seafoam)] to-[var(--accent-magenta)]">
                <Shield className="w-6 h-6 text-[var(--text-inverse)]" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-[var(--text-primary)]">OSINT Suite</h1>
                <p className="text-sm text-[var(--text-muted)]">Professional Intelligence Platform</p>
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
                  className="w-full pl-12 pr-20 py-3 rounded-2xl bg-[var(--glass-surface)] border border-[var(--glass-border)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-blue)] focus:border-[var(--accent-seafoam)] backdrop-blur-xl"
                />
                <Search className="absolute left-4 top-3 w-4 h-4 text-[var(--accent-seafoam)]" />
                <button
                  onClick={handleSearch}
                  className="absolute right-2 top-1 px-4 py-1.5 text-sm font-medium rounded-xl bg-[var(--accent-blue)] text-[var(--text-inverse)] hover:bg-[var(--accent-seafoam)] transition-colors shadow-[0_0_18px_rgba(56,189,248,0.45)]"
                >
                  Search
                </button>
              </div>
            </div>

            {/* Status and Actions */}
            <div className="flex items-center space-x-4">
              <div
                className={`flex items-center space-x-2 px-4 py-1.5 rounded-full text-sm glass bg-[var(--glass-surface)]/90 border border-[var(--glass-border)]/70 shadow-[0_0_12px_rgba(45,212,191,0.25)] ${statusTextClass}`}
              >
                <div
                  className={`w-2 h-2 rounded-full shadow-[0_0_10px_rgba(56,189,248,0.55)] ${statusDotClass}`}
                ></div>
                <span className="font-medium tracking-wide">{statusLabel}</span>
              </div>

              {user ? (
                <>
                  <div className="hidden md:flex items-center space-x-2 px-3 py-1.5 rounded-xl glass bg-[var(--glass-surface)] border border-[var(--glass-border)]/60 text-[var(--accent-gold)]">
                    <User className="w-4 h-4" />
                    <span className="font-medium">{user.username}</span>
                  </div>
                  <button
                    onClick={handleLogout}
                    className="p-2 rounded-xl text-[var(--accent-silver)] hover:text-[var(--accent-gold)] hover:bg-[var(--glass-hover)] transition-colors"
                    title="Logout"
                  >
                    <LogOut className="w-5 h-5" />
                  </button>
                </>
              ) : (
                <button
                  onClick={() => setIsLoginModalOpen(true)}
                  className="flex items-center space-x-2 px-4 py-2 rounded-xl bg-gradient-to-r from-[var(--accent-blue)] to-[var(--accent-seafoam)] text-[var(--text-inverse)] shadow-[0_0_20px_rgba(56,189,248,0.45)] hover:from-[var(--accent-seafoam)] hover:to-[var(--accent-blue)] transition-all"
                >
                  <LogIn className="w-4 h-4" />
                  <span>Login</span>
                </button>
              )}

              <button
                onClick={() => setIsSettingsModalOpen(true)}
                className="p-2 rounded-xl text-[var(--accent-silver)] hover:text-[var(--accent-blue)] hover:bg-[var(--glass-hover)] transition-colors"
                title="Settings"
              >
                <Settings className="w-5 h-5" />
              </button>

              <button
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="p-2 rounded-xl text-[var(--accent-silver)] hover:text-[var(--accent-blue)] hover:bg-[var(--glass-hover)] transition-colors lg:hidden"
              >
                <Menu className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <aside
          className={`fixed inset-y-0 left-0 z-50 w-64 glass border-r border-[var(--glass-border)]/70 bg-[var(--glass-surface)] shadow-[0_30px_80px_rgba(2,6,23,0.65)] transform ${
            sidebarOpen ? 'translate-x-0' : '-translate-x-full'
          } transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:inset-0`}
        >
          <div className="flex flex-col h-full pt-16 lg:pt-0">
            {/* Navigation */}
            <nav className="flex-1 px-4 py-6">
              <div className="space-y-2">
                {navigation.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => {
                        setActiveTab(item.id);
                        setSidebarOpen(false);
                      }}
                      className={`group relative w-full flex items-center space-x-3 px-4 py-3 rounded-xl transition-all duration-300 ${
                        isActive
                          ? 'bg-[var(--glass-hover)] text-[var(--text-primary)] shadow-[0_0_25px_rgba(56,189,248,0.25)]'
                          : 'text-[var(--text-muted)] hover:bg-[var(--glass-hover)] hover:text-[var(--text-primary)]'
                      }`}
                    >
                      {isActive && (
                        <div className="absolute left-0 top-0 bottom-0 w-1.5 rounded-r-full bg-gradient-to-b from-[var(--accent-blue)] via-[var(--accent-seafoam)] to-[var(--accent-gold)] shadow-[0_0_12px_rgba(56,189,248,0.45)]" />
                      )}
                      <Icon className={`w-5 h-5 transition-colors ${isActive ? item.color : 'text-[var(--accent-silver)] group-hover:text-[var(--accent-blue)]'}`} />
                      <span className="font-medium tracking-wide">{item.name}</span>
                      {isActive && <ChevronRight className="w-4 h-4 ml-auto text-[var(--accent-gold)]" />}
                    </button>
                  );
                })}
              </div>
            </nav>

            {/* Quick Stats */}
            <div className="px-4 pb-6">
              <div className="glass rounded-xl p-4 border border-[var(--glass-border)]/70 bg-[var(--glass-surface)] text-[var(--text-primary)]">
                <h3 className="text-sm font-semibold mb-3 text-[var(--accent-silver)] uppercase tracking-wider">System Status</h3>
                <div className="space-y-2 text-xs text-[var(--text-secondary)]">
                  <div className="flex justify-between">
                    <span className="opacity-70">Active Modules</span>
                    <span className="font-semibold text-[var(--accent-seafoam)]">18</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="opacity-70">Data Sources</span>
                    <span className="font-semibold text-[var(--accent-blue)]">50+</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="opacity-70">Queries Today</span>
                    <span className="font-semibold text-[var(--accent-gold)]">247</span>
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
                  <div className="relative overflow-hidden glass rounded-2xl p-8 border border-[var(--glass-border)]/60 bg-[var(--glass-elevated)]">
                    <div className="absolute inset-0 bg-gradient-to-r from-[var(--accent-blue)]/30 via-[var(--accent-seafoam)]/20 to-transparent" />
                    <div className="relative flex items-center justify-between">
                      <div>
                        <h2 className="text-3xl font-bold mb-2 text-[var(--text-primary)]">Welcome to OSINT Suite</h2>
                        <p className="text-lg text-[var(--text-secondary)]">Professional intelligence gathering and analysis platform</p>
                      </div>
                      <div className="hidden md:block">
                        <Shield className="w-16 h-16 text-[var(--accent-seafoam)]/70" />
                      </div>
                    </div>
                  </div>

                  {/* Stats Cards */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 stagger-fade-in">
                    {stats.map((stat, index) => {
                      const Icon = stat.icon;
                      return (
                        <Card
                          key={stat.label}
                          className="p-6 card-interactive"
                          elevation="base"
                          interactive
                        >
                          <div className="flex items-center justify-between mb-4">
                            <div className="p-3 rounded-xl glass bg-[var(--glass-surface)]/70 border border-[var(--glass-border)]/60">
                              <Icon className={`w-6 h-6 ${stat.color}`} />
                            </div>
                            <span className={`text-sm font-semibold ${stat.color}`}>{stat.trend}</span>
                          </div>
                          <div>
                            <p className="text-2xl font-bold mb-1 text-[var(--text-primary)]">{stat.value}</p>
                            <p className="text-sm text-[var(--text-secondary)]/80">{stat.label}</p>
                          </div>
                        </Card>
                      );
                    })}
                  </div>

                  {/* Recent Activity & Quick Actions */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    {/* Recent Activity */}
                    <Card className="p-6" elevation="base">
                      <div className="flex items-center justify-between mb-6">
                        <h3 className="text-lg font-semibold flex items-center text-[var(--text-primary)]">
                          <Activity className="w-5 h-5 mr-2 text-[var(--accent-blue)]" />
                          Recent Activity
                        </h3>
                        <button className="text-[var(--accent-blue)] hover:text-[var(--accent-seafoam)] text-sm font-medium transition-colors">
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
                          <div key={index} className="flex items-center space-x-4 p-4 rounded-xl glass border border-[var(--glass-border)]/60 bg-[var(--glass-surface)]/80">
                            <div
                              className={`w-3 h-3 rounded-full shadow-[0_0_8px_rgba(56,189,248,0.45)] ${
                                activity.status === 'success'
                                  ? 'bg-[var(--accent-seafoam)]'
                                  : activity.status === 'warning'
                                  ? 'bg-[var(--accent-gold)]'
                                  : 'bg-[var(--accent-silver)]'
                              }`}
                            ></div>
                            <div className="flex-1">
                              <p className="text-sm font-medium text-[var(--text-primary)]">{activity.action}</p>
                              <p className="text-xs text-[var(--text-secondary)]/80">{activity.target}</p>
                            </div>
                            <span className="text-xs text-[var(--text-secondary)]/70">{activity.time}</span>
                          </div>
                        ))}
                      </div>
                    </Card>

                    {/* Quick Actions */}
                    <Card className="p-6" elevation="hover">
                      <div className="flex items-center justify-between mb-6">
                        <h3 className="text-lg font-semibold text-[var(--text-primary)] flex items-center">
                          <Lightning className="w-5 h-5 mr-2 text-[var(--accent-magenta)]" />
                          Quick Actions
                        </h3>
                        <button className="text-[var(--accent-seafoam)] hover:text-[var(--accent-blue)] text-sm font-medium transition-colors">
                          Customize
                        </button>
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        {[
                          { name: 'Domain Lookup', icon: Globe, accent: 'from-[var(--accent-blue)] to-[var(--accent-seafoam)]' },
                          { name: 'Email Check', icon: Mail, accent: 'from-[var(--accent-seafoam)] to-[var(--accent-blue)]' },
                          { name: 'Social Scan', icon: Users, accent: 'from-[var(--accent-magenta)] to-[var(--accent-blue)]' },
                          { name: 'IP Analysis', icon: Server, accent: 'from-[var(--accent-gold)] to-[var(--accent-seafoam)]' }
                        ].map((action, index) => {
                          const Icon = action.icon;
                          return (
                            <button
                              key={index}
                              className={`group relative overflow-hidden p-4 rounded-xl glass border border-[var(--glass-border)]/60 text-[var(--text-secondary)] transition-all hover:-translate-y-[2px]`}
                            >
                              <div className={`absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity bg-gradient-to-br ${action.accent}`} />
                              <div className="relative">
                                <Icon className="w-6 h-6 mx-auto mb-2 text-[var(--accent-silver)] group-hover:text-[var(--text-inverse)] transition-colors" />
                                <span className="text-sm font-medium group-hover:text-[var(--text-inverse)] transition-colors">
                                  {action.name}
                                </span>
                              </div>
                            </button>
                          );
                        })}
                      </div>
                    </Card>
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
                      <h2 className="text-3xl font-bold text-[var(--text-primary)]">OSINT Modules</h2>
                      <p className="text-[var(--text-secondary)]/80 mt-1">Choose and run intelligence gathering tools</p>
                    </div>
                    <div className="mt-4 sm:mt-0 flex space-x-3">
                      <select className="glass bg-[var(--glass-surface)] border border-[var(--glass-border)]/70 text-[var(--text-primary)] px-4 py-2 rounded-xl focus:outline-none focus:ring-2 focus:ring-[var(--accent-blue)]">
                        <option>All Categories</option>
                        <option>Network</option>
                        <option>Social</option>
                        <option>Research</option>
                        <option>Code</option>
                        <option>Business</option>
                      </select>
                      <button className="px-6 py-2 rounded-xl bg-gradient-to-r from-[var(--accent-blue)] to-[var(--accent-seafoam)] text-[var(--text-inverse)] shadow-[0_0_18px_rgba(56,189,248,0.35)] hover:from-[var(--accent-seafoam)] hover:to-[var(--accent-blue)] transition-all flex items-center space-x-2">
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
                          className="glass rounded-2xl p-6 border border-[var(--glass-border)]/70 bg-[var(--glass-surface)] shadow-[0_20px_45px_rgba(2,6,23,0.45)] hover:-translate-y-[4px] transition-all duration-300 hover:bg-[var(--glass-hover)]"
                        >
                          <div className="flex items-start justify-between mb-4">
                            <div className="p-3 rounded-xl bg-[var(--glass-elevated)]/60 border border-[var(--glass-border)]/60 shadow-[0_0_20px_rgba(56,189,248,0.25)]">
                              <Icon className="w-6 h-6 text-[var(--accent-blue)]" />
                            </div>
                            <div
                              className={`px-2 py-1 rounded-full text-xs font-medium uppercase tracking-wider ${
                                module.status === 'active'
                                  ? 'bg-[var(--glass-surface)] text-[var(--accent-seafoam)] border border-[var(--glass-border)]/50'
                                  : 'bg-[var(--glass-surface)] text-[var(--accent-silver)] border border-[var(--glass-border)]/50'
                              }`}
                            >
                              {module.status}
                            </div>
                          </div>

                          <h3 className="text-lg font-semibold text-[var(--text-primary)] mb-2">{module.name}</h3>
                          <p className="text-[var(--text-secondary)] text-sm mb-4">{module.description}</p>

                          <div className="flex items-center justify-between text-xs text-[var(--text-secondary)]/80 mb-4">
                            <span className="px-2 py-1 rounded bg-[var(--glass-surface)] border border-[var(--glass-border)]/50">
                              {module.category}
                            </span>
                            <span>{module.lastUsed}</span>
                          </div>

                          <button
                            onClick={() => handleModuleRun(module.id)}
                            disabled={isLoading && selectedModule === module.id}
                            className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-[var(--accent-blue)] to-[var(--accent-seafoam)] text-[var(--text-inverse)] hover:from-[var(--accent-seafoam)] hover:to-[var(--accent-blue)] disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2"
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
                    <h2 className="text-3xl font-bold text-[var(--text-primary)]">Intelligence Center</h2>
                    <p className="text-[var(--text-secondary)]/80 mt-1">Real-time intelligence gathering and monitoring</p>
                  </div>

                  {/* Intelligence Input Form */}
                  <div className="glass rounded-2xl p-8 border border-[var(--glass-border)]/70 bg-[var(--glass-surface)] shadow-[0_28px_70px_rgba(2,6,23,0.55)]">
                    <div className="mb-6">
                      <h3 className="text-xl font-semibold text-[var(--text-primary)] mb-2">New Intelligence Query</h3>
                      <p className="text-[var(--text-secondary)]/80">Configure your intelligence gathering parameters</p>
                    </div>

                    <div className="space-y-6">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
                            Target Type
                          </label>
                          <select className="w-full glass border border-[var(--glass-border)]/60 rounded-2xl px-4 py-3 bg-[var(--glass-surface)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-blue)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)]">
                            <option>Domain</option>
                            <option>Email</option>
                            <option>Username</option>
                            <option>IP Address</option>
                            <option>Company</option>
                            <option>Phone Number</option>
                          </select>
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
                            Priority Level
                          </label>
                          <select className="w-full glass border border-[var(--glass-border)]/60 rounded-2xl px-4 py-3 bg-[var(--glass-surface)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-blue)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)]">
                            <option>Low</option>
                            <option>Medium</option>
                            <option>High</option>
                            <option>Critical</option>
                          </select>
                        </div>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
                          Query Details
                        </label>
                        <textarea
                          rows={4}
                          placeholder="Enter your intelligence query details..."
                          className="w-full glass border border-[var(--glass-border)]/60 rounded-2xl px-4 py-3 bg-[var(--glass-surface)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-blue)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)]"
                        />
                      </div>

                      <div className="flex flex-wrap gap-4">
                        <label className="flex items-center space-x-2">
                          <input type="checkbox" className="rounded border-[var(--glass-border)]/60 text-[var(--accent-blue)] focus:ring-[var(--accent-blue)]" />
                          <span className="text-sm text-[var(--text-secondary)]">Include passive sources</span>
                        </label>
                        <label className="flex items-center space-x-2">
                          <input type="checkbox" className="rounded border-[var(--glass-border)]/60 text-[var(--accent-blue)] focus:ring-[var(--accent-blue)]" />
                          <span className="text-sm text-[var(--text-secondary)]">Real-time monitoring</span>
                        </label>
                        <label className="flex items-center space-x-2">
                          <input type="checkbox" className="rounded border-[var(--glass-border)]/60 text-[var(--accent-blue)] focus:ring-[var(--accent-blue)]" />
                          <span className="text-sm text-[var(--text-secondary)]">Advanced analysis</span>
                        </label>
                      </div>

                      <div className="flex space-x-4">
                        <button className="bg-[var(--accent-blue)] text-[var(--text-inverse)] px-8 py-3 rounded-lg hover:bg-[var(--accent-seafoam)] transition-colors flex items-center space-x-2">
                          <Search className="w-4 h-4" />
                          <span>Start Intelligence Gathering</span>
                        </button>
                        <button className="glass border border-[var(--glass-border)]/70 text-[var(--text-secondary)] px-6 py-3 rounded-xl hover:bg-[var(--glass-hover)] hover:text-[var(--accent-blue)] transition-colors">
                          Save Query
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Active Intelligence Operations */}
                  <div className="glass rounded-2xl p-6 border border-[var(--glass-border)]/70 bg-[var(--glass-surface)] shadow-[0_24px_60px_rgba(2,6,23,0.5)]">
                    <div className="flex items-center justify-between mb-6">
                      <h3 className="text-lg font-semibold text-[var(--text-primary)]">Active Operations</h3>
                      <button className="text-[var(--accent-blue)] hover:text-[var(--accent-blue)] text-sm font-medium">
                        View All
                      </button>
                    </div>
                    <div className="space-y-4">
                      {[{ id: 'op-001', target: 'example.com', type: 'Domain Analysis', progress: 75, status: 'running' },
                        { id: 'op-002', target: 'john.doe@email.com', type: 'Email Intelligence', progress: 45, status: 'running' },
                        { id: 'op-003', target: 'techcorp.com', type: 'Corporate Intel', progress: 100, status: 'completed' }].map((op) => (
                        <div key={op.id} className="flex items-center space-x-4 p-4 glass rounded-2xl border border-[var(--glass-border)]/60 bg-[var(--glass-surface)]/85">
                          <div
                            className={`w-3 h-3 rounded-full shadow-[0_0_8px_rgba(56,189,248,0.4)] ${
                              op.status === 'completed'
                                ? 'bg-[var(--accent-gold)]'
                                : 'bg-[var(--accent-blue)]'
                            }`}
                          ></div>
                          <div className="flex-1">
                            <div className="flex items-center justify-between mb-1">
                              <span className="font-medium text-[var(--text-primary)]">{op.type}</span>
                              <span className="text-sm text-[var(--text-secondary)]/80">{op.progress}%</span>
                            </div>
                            <div className="w-full bg-[var(--glass-surface)] rounded-full h-2 mb-2">
                              <div
                                className="bg-gradient-to-r from-[var(--accent-blue)] to-[var(--accent-seafoam)] h-2 rounded-full transition-all duration-300"
                                style={{ width: `${op.progress}%` }}
                              ></div>
                            </div>
                            <span className="text-sm text-[var(--text-secondary)]/80">{op.target}</span>
                          </div>
                          <button className="text-[var(--text-secondary)]/70 hover:text-[var(--accent-magenta)]">
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
                    <h2 className="text-3xl font-bold text-[var(--text-primary)]">AI Analysis Center</h2>
                    <p className="text-[var(--text-secondary)]/80 mt-1">Advanced AI-powered intelligence analysis</p>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    {/* Analysis Input */}
                    <div className="glass rounded-2xl p-8 border border-[var(--glass-border)]/70 bg-[var(--glass-surface)] shadow-[0_28px_70px_rgba(2,6,23,0.55)]">
                      <div className="mb-6">
                        <h3 className="text-xl font-semibold text-[var(--text-primary)] mb-2">Intelligence Analysis</h3>
                        <p className="text-[var(--text-secondary)]/80">Upload data for AI-powered analysis</p>
                      </div>

                      <div className="space-y-6">
                        <div>
                          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
                            Analysis Type
                          </label>
                          <select className="w-full glass border border-[var(--glass-border)]/60 rounded-2xl px-4 py-3 bg-[var(--glass-surface)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-blue)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)]">
                            <option>Pattern Recognition</option>
                            <option>Risk Assessment</option>
                            <option>Correlation Analysis</option>
                            <option>Threat Intelligence</option>
                            <option>Behavioral Analysis</option>
                          </select>
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
                            Data Input
                          </label>
                          <textarea
                            rows={6}
                            placeholder="Paste intelligence data for analysis..."
                            className="w-full glass border border-[var(--glass-border)]/60 rounded-2xl px-4 py-3 bg-[var(--glass-surface)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-blue)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)]"
                          />
                        </div>

                        <div className="flex space-x-4">
                          <button className="bg-purple-600 text-[var(--text-inverse)] px-8 py-3 rounded-lg hover:bg-purple-700 transition-colors flex items-center space-x-2">
                            <Brain className="w-4 h-4" />
                            <span>Analyze</span>
                          </button>
                          <button className="glass border border-[var(--glass-border)]/70 text-[var(--text-secondary)] px-6 py-3 rounded-xl hover:bg-[var(--glass-hover)] hover:text-[var(--accent-blue)] transition-colors flex items-center space-x-2">
                            <Upload className="w-4 h-4" />
                            <span>Upload File</span>
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Analysis Results */}
                    <div className="glass rounded-2xl p-8 border border-[var(--glass-border)]/70 bg-[var(--glass-surface)] shadow-[0_28px_70px_rgba(2,6,23,0.55)]">
                      <div className="mb-6">
                        <h3 className="text-xl font-semibold text-[var(--text-primary)] mb-2">Analysis Results</h3>
                        <p className="text-[var(--text-secondary)]/80">AI-generated insights and findings</p>
                      </div>

                      <div className="space-y-6">
                        <div className="p-4 bg-[var(--glass-surface)] border border-green-200 rounded-lg">
                          <div className="flex items-center space-x-2 mb-3">
                            <CheckCircle className="w-5 h-5 text-[var(--accent-seafoam)]" />
                            <span className="font-medium text-green-800">High Confidence Match</span>
                          </div>
                          <p className="text-sm text-[var(--accent-seafoam)]">
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

                        <div className="p-4 bg-[var(--glass-surface)] border border-blue-200 rounded-lg">
                          <div className="flex items-center space-x-2 mb-3">
                            <Radar className="w-5 h-5 text-[var(--accent-blue)]" />
                            <span className="font-medium text-blue-800">Intelligence Insight</span>
                          </div>
                          <p className="text-sm text-[var(--accent-blue)]">
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
                      <h2 className="text-3xl font-bold text-[var(--text-primary)]">Investigations</h2>
                      <p className="text-[var(--text-secondary)]/80 mt-1">Manage and track intelligence investigations</p>
                    </div>
                    <button className="mt-4 sm:mt-0 bg-[var(--accent-blue)] text-[var(--text-inverse)] px-6 py-3 rounded-lg hover:bg-[var(--accent-seafoam)] transition-colors flex items-center space-x-2">
                      <Plus className="w-4 h-4" />
                      <span>New Investigation</span>
                    </button>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                    {/* Investigation Stats */}
                    <div className="glass rounded-2xl p-6 border border-[var(--glass-border)]/70 bg-[var(--glass-surface)] shadow-[0_24px_60px_rgba(2,6,23,0.5)]">
                      <h3 className="text-lg font-semibold text-[var(--text-primary)] mb-6">Investigation Stats</h3>
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <span className="text-[var(--text-secondary)]/80">Active Cases</span>
                          <span className="font-bold text-[var(--text-primary)]">8</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-[var(--text-secondary)]/80">Completed</span>
                          <span className="font-bold text-[var(--accent-seafoam)]">24</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-[var(--text-secondary)]/80">High Priority</span>
                          <span className="font-bold text-[var(--accent-magenta)]">3</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-[var(--text-secondary)]/80">This Month</span>
                          <span className="font-bold text-[var(--accent-blue)]">12</span>
                        </div>
                      </div>
                    </div>

                    {/* Recent Investigations */}
                    <div className="lg:col-span-2 glass rounded-2xl p-6 border border-[var(--glass-border)]/70 bg-[var(--glass-surface)] shadow-[0_24px_60px_rgba(2,6,23,0.5)]">
                      <h3 className="text-lg font-semibold text-[var(--text-primary)] mb-6">Recent Investigations</h3>
                      <div className="space-y-4">
                        {[
                          { id: 'INV-2025-001', title: 'Corporate Espionage Investigation', status: 'active', priority: 'high', progress: 75 },
                          { id: 'INV-2025-002', title: 'Social Media Harassment Case', status: 'active', priority: 'medium', progress: 45 },
                          { id: 'INV-2025-003', title: 'Financial Fraud Analysis', status: 'completed', priority: 'high', progress: 100 },
                          { id: 'INV-2025-004', title: 'IP Theft Investigation', status: 'active', priority: 'medium', progress: 30 }
                        ].map((inv) => (
                        <div key={inv.id} className="flex items-center space-x-4 p-4 glass border border-[var(--glass-border)]/70 rounded-2xl hover:bg-[var(--glass-hover)] transition-colors">
                            <div className={`w-3 h-3 rounded-full ${
                              inv.status === 'active' ? 'bg-[var(--accent-blue)]' : 'bg-[var(--accent-seafoam)]'
                            }`}></div>
                            <div className="flex-1">
                              <div className="flex items-center justify-between mb-1">
                                <span className="font-medium text-[var(--text-primary)]">{inv.title}</span>
                                <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                                  inv.priority === 'high' ? 'bg-red-100 text-red-700' :
                                  inv.priority === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                                  'bg-[var(--glass-surface)] text-[var(--accent-seafoam)]'
                                }`}>
                                  {inv.priority}
                                </span>
                              </div>
                              <div className="flex items-center justify-between text-sm text-[var(--text-secondary)]/80">
                                <span>{inv.id}</span>
                                <span>{inv.progress}% complete</span>
                              </div>
                          <div className="w-full bg-[var(--glass-surface)] rounded-full h-2 mt-2">
                                <div
                                  className="bg-[var(--accent-blue)] h-2 rounded-full transition-all duration-300"
                                  style={{ width: `${inv.progress}%` }}
                                ></div>
                              </div>
                            </div>
                            <button className="text-[var(--text-secondary)]/70 hover:text-[var(--text-secondary)]">
                              <ChevronRight className="w-5 h-5" />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {activeTab === 'assistant' && (
                <motion.div
                  key="assistant"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-8"
                >
                  <ChatInterface
                    investigationId={selectedInvestigationId ?? undefined}
                    apiUrl={API_URL}
                  />
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
                      <h2 className="text-3xl font-bold text-[var(--text-primary)]">Reports & Analytics</h2>
                      <p className="text-[var(--text-secondary)]/80 mt-1">Generate and view intelligence reports</p>
                    </div>
                    <div className="mt-4 sm:mt-0 flex space-x-3">
                      <button className="glass border border-[var(--glass-border)]/70 text-[var(--text-secondary)] px-4 py-2 rounded-xl hover:bg-[var(--glass-hover)] hover:text-[var(--accent-blue)] transition-colors flex items-center space-x-2">
                        <Download className="w-4 h-4" />
                        <span>Export All</span>
                      </button>
                      <button className="bg-[var(--accent-blue)] text-[var(--text-inverse)] px-6 py-3 rounded-lg hover:bg-[var(--accent-seafoam)] transition-colors flex items-center space-x-2">
                        <Plus className="w-4 h-4" />
                        <span>Generate Report</span>
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    {/* Report Generation */}
                    <div className="glass rounded-2xl p-8 border border-[var(--glass-border)]/70 bg-[var(--glass-surface)] shadow-[0_28px_70px_rgba(2,6,23,0.55)]">
                      <div className="mb-6">
                        <h3 className="text-xl font-semibold text-[var(--text-primary)] mb-2">Generate New Report</h3>
                        <p className="text-[var(--text-secondary)]/80">Create comprehensive intelligence reports</p>
                      </div>

                      <div className="space-y-6">
                        <div>
                          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
                            Report Type
                          </label>
                          <select className="w-full glass border border-[var(--glass-border)]/60 rounded-2xl px-4 py-3 bg-[var(--glass-surface)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-blue)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)]">
                            <option>Executive Summary</option>
                            <option>Technical Analysis</option>
                            <option>Threat Assessment</option>
                            <option>Investigation Timeline</option>
                            <option>Data Analytics</option>
                          </select>
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
                            Date Range
                          </label>
                          <div className="grid grid-cols-2 gap-4">
                            <input
                              type="date"
                              className="glass border border-[var(--glass-border)]/60 rounded-2xl px-4 py-3 bg-[var(--glass-surface)] text-[var(--text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-blue)] focus:border-[var(--accent-seafoam)]"
                            />
                            <input
                              type="date"
                              className="glass border border-[var(--glass-border)]/60 rounded-2xl px-4 py-3 bg-[var(--glass-surface)] text-[var(--text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-blue)] focus:border-[var(--accent-seafoam)]"
                            />
                          </div>
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-4">
                            Include Data Sources
                          </label>
                          <div className="space-y-3">
                            {['Domain Intelligence', 'Social Media', 'Email Analysis', 'Network Data', 'Academic Research'].map((source) => (
                              <label key={source} className="flex items-center space-x-3">
                                <input type="checkbox" className="rounded border-[var(--glass-border)]/60 text-[var(--accent-blue)] focus:ring-[var(--accent-blue)]" />
                                <span className="text-sm text-[var(--text-secondary)]">{source}</span>
                              </label>
                            ))}
                          </div>
                        </div>

                        <button className="w-full bg-[var(--accent-blue)] text-[var(--text-inverse)] py-3 px-4 rounded-lg hover:bg-[var(--accent-seafoam)] transition-colors flex items-center justify-center space-x-2">
                          <FileSearch className="w-4 h-4" />
                          <span>Generate Report</span>
                        </button>
                      </div>
                    </div>

                    {/* Recent Reports */}
                    <div className="glass rounded-2xl p-8 border border-[var(--glass-border)]/70 bg-[var(--glass-surface)] shadow-[0_28px_70px_rgba(2,6,23,0.55)]">
                      <div className="mb-6">
                        <h3 className="text-xl font-semibold text-[var(--text-primary)] mb-2">Recent Reports</h3>
                        <p className="text-[var(--text-secondary)]/80">Access your generated intelligence reports</p>
                      </div>

                      <div className="space-y-4">
                        {[
                          { title: 'Monthly Intelligence Summary', date: '2025-09-15', type: 'Executive', size: '2.4 MB' },
                          { title: 'Threat Actor Analysis', date: '2025-09-12', type: 'Technical', size: '1.8 MB' },
                          { title: 'Network Security Assessment', date: '2025-09-10', type: 'Assessment', size: '3.1 MB' },
                          { title: 'Social Media Monitoring Report', date: '2025-09-08', type: 'Analytics', size: '956 KB' }
                        ].map((report, index) => (
                        <div key={report.title + index} className="flex items-center space-x-4 p-4 glass border border-[var(--glass-border)]/70 rounded-2xl hover:bg-[var(--glass-hover)] transition-colors">
                            <div className="bg-[var(--glass-surface)] p-3 rounded-lg">
                              <BarChart3 className="w-5 h-5 text-[var(--accent-blue)]" />
                            </div>
                            <div className="flex-1">
                              <h4 className="font-medium text-[var(--text-primary)]">{report.title}</h4>
                              <div className="flex items-center space-x-4 text-sm text-[var(--text-secondary)]/80 mt-1">
                                <span>{report.date}</span>
                                <span>{report.type}</span>
                                <span>{report.size}</span>
                              </div>
                            </div>
                            <button className="text-[var(--text-secondary)]/70 hover:text-[var(--text-secondary)]">
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
                    <h2 className="text-3xl font-bold text-[var(--text-primary)]">Settings</h2>
                    <p className="text-[var(--text-secondary)]/80 mt-1">Configure your OSINT Suite preferences</p>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    {/* System Settings */}
                    <div className="glass rounded-2xl p-8 border border-[var(--glass-border)]/70 bg-[var(--glass-surface)] shadow-[0_28px_70px_rgba(2,6,23,0.55)]">
                      <div className="mb-6">
                        <h3 className="text-xl font-semibold text-[var(--text-primary)] mb-2">System Configuration</h3>
                        <p className="text-[var(--text-secondary)]/80">Manage system-wide settings and preferences</p>
                      </div>

                      <div className="space-y-6">
                        <div>
                          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
                            Max Concurrent Operations
                          </label>
                          <input
                            type="number"
                            defaultValue="5"
                            className="w-full glass border border-[var(--glass-border)]/60 rounded-2xl px-4 py-3 bg-[var(--glass-surface)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-blue)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)]"
                          />
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
                            Data Retention (days)
                          </label>
                          <input
                            type="number"
                            defaultValue="90"
                            className="w-full glass border border-[var(--glass-border)]/60 rounded-2xl px-4 py-3 bg-[var(--glass-surface)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-blue)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)]"
                          />
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
                            Report Storage Path
                          </label>
                          <input
                            type="text"
                            defaultValue="/opt/osint/reports"
                            className="w-full glass border border-[var(--glass-border)]/60 rounded-2xl px-4 py-3 bg-[var(--glass-surface)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-blue)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)]"
                          />
                        </div>

                        <div className="flex items-center justify-between">
                          <span className="text-[var(--text-secondary)]">Auto-save investigations</span>
                          <label className="relative inline-flex items-center cursor-pointer">
                            <input type="checkbox" className="sr-only peer" defaultChecked />
                            <div className="w-11 h-6 bg-[var(--glass-surface)] peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-[var(--accent-blue)] rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-[var(--text-inverse)] after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-[var(--accent-seafoam)]"></div>
                          </label>
                        </div>
                      </div>
                    </div>

                    {/* API Configuration */}
                    <div className="glass rounded-2xl p-8 border border-[var(--glass-border)]/70 bg-[var(--glass-surface)] shadow-[0_28px_70px_rgba(2,6,23,0.55)]">
                      <div className="mb-6">
                        <h3 className="text-xl font-semibold text-[var(--text-primary)] mb-2">API Configuration</h3>
                        <p className="text-[var(--text-secondary)]/80">Manage external API keys and integrations</p>
                      </div>

                      <div className="space-y-4">
                        {[
                          { name: 'Shodan API', status: 'configured', lastUsed: '2 hours ago' },
                          { name: 'Hunter.io API', status: 'configured', lastUsed: '1 day ago' },
                          { name: 'OpenAI API', status: 'configured', lastUsed: '30 mins ago' },
                          { name: 'VirusTotal API', status: 'not_configured', lastUsed: 'never' }
                        ].map((api, index) => (
                          <div key={index} className="flex items-center justify-between p-4 border border-[var(--glass-border)]/70 rounded-lg">
                            <div>
                              <span className="font-medium text-[var(--text-primary)]">{api.name}</span>
                              <p className="text-sm text-[var(--text-secondary)]/80">{api.lastUsed}</p>
                            </div>
                            <div className="flex items-center space-x-2">
                              <div className={`w-2 h-2 rounded-full ${
                                api.status === 'configured' ? 'bg-[var(--accent-seafoam)]' : 'bg-red-500'
                              }`}></div>
                              <button className="text-[var(--accent-blue)] hover:text-[var(--accent-blue)] text-sm font-medium">
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

      {/* Modals */}
      <LoginModal
        isOpen={isLoginModalOpen}
        onClose={() => setIsLoginModalOpen(false)}
        onLoginSuccess={handleLoginSuccess}
        apiUrl={API_URL}
      />
      <SettingsModal
        isOpen={isSettingsModalOpen}
        onClose={() => setIsSettingsModalOpen(false)}
      />
      <DomainInvestigationModal
        isOpen={isDomainModalOpen}
        onClose={() => setIsDomainModalOpen(false)}
        apiUrl={API_URL}
      />
    </div>
  );
};

export default ModernApp;
