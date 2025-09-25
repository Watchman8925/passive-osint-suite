import React, { useState, useEffect } from 'react';
import { Search, Filter, Eye, Download, Calendar, User, AlertTriangle, Info, X } from 'lucide-react';
import { securityAPI, SecurityEvent } from '../../services/securityAPI';

interface SecurityEventDetailsProps {
  isOpen: boolean;
  onClose: () => void;
  event?: SecurityEvent;
}

export const SecurityEventDetails: React.FC<SecurityEventDetailsProps> = ({
  isOpen,
  onClose,
  event
}) => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [filteredEvents, setFilteredEvents] = useState<SecurityEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(event || null);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [dateRange, setDateRange] = useState<{start: string, end: string}>({
    start: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
    end: new Date().toISOString().split('T')[0]
  });

  useEffect(() => {
    if (isOpen) {
      loadEvents();
    }
  }, [isOpen]);

  useEffect(() => {
    filterEvents();
  }, [events, searchTerm, severityFilter, typeFilter, dateRange]);

  const loadEvents = async () => {
    try {
      setLoading(true);
      const eventsData = await securityAPI.getSecurityEvents(1000); // Load more events for detailed view
      setEvents(eventsData);
    } catch (err) {
      console.error('Failed to load security events:', err);
    } finally {
      setLoading(false);
    }
  };

  const filterEvents = () => {
    let filtered = events;

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(event =>
        event.event_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
        event.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (event.user_id && event.user_id.toLowerCase().includes(searchTerm.toLowerCase()))
      );
    }

    // Severity filter
    if (severityFilter !== 'all') {
      filtered = filtered.filter(event => event.severity === severityFilter);
    }

    // Type filter
    if (typeFilter !== 'all') {
      filtered = filtered.filter(event => event.event_type === typeFilter);
    }

    // Date range filter
    if (dateRange.start && dateRange.end) {
      const startDate = new Date(dateRange.start);
      const endDate = new Date(dateRange.end);
      endDate.setHours(23, 59, 59, 999); // Include the entire end date

      filtered = filtered.filter(event => {
        const eventDate = new Date(event.timestamp);
        return eventDate >= startDate && eventDate <= endDate;
      });
    }

    setFilteredEvents(filtered);
  };

  const exportEvents = () => {
    const csvContent = [
      ['Timestamp', 'Event Type', 'Severity', 'User', 'Description', 'IP Address', 'User Agent'].join(','),
      ...filteredEvents.map(event => [
        event.timestamp,
        event.event_type,
        event.severity,
        event.user_id || '',
        `"${event.description.replace(/"/g, '""')}"`,
        event.metadata?.ip_address || '',
        `"${event.metadata?.user_agent?.replace(/"/g, '""') || ''}"`
      ].join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-events-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getEventTypeIcon = (eventType: string) => {
    if (eventType.toLowerCase().includes('login')) return <User className="h-4 w-4" />;
    if (eventType.toLowerCase().includes('alert')) return <AlertTriangle className="h-4 w-4" />;
    return <Info className="h-4 w-4" />;
  };

  const uniqueEventTypes = Array.from(new Set(events.map(e => e.event_type)));
  const uniqueSeverities = Array.from(new Set(events.map(e => e.severity)));

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
      <div className="relative top-4 mx-auto p-5 border w-11/12 max-w-7xl shadow-lg rounded-md bg-white max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-gray-900">Security Event Details</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        {/* Filters */}
        <div className="bg-gray-50 p-4 rounded-lg mb-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Search */}
            <div className="relative">
              <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
              <input
                type="text"
                placeholder="Search events..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              />
            </div>

            {/* Severity Filter */}
            <div>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="w-full border border-gray-300 rounded-md px-3 py-2 focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="all">All Severities</option>
                {uniqueSeverities.map(severity => (
                  <option key={severity} value={severity}>{severity}</option>
                ))}
              </select>
            </div>

            {/* Event Type Filter */}
            <div>
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="w-full border border-gray-300 rounded-md px-3 py-2 focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="all">All Event Types</option>
                {uniqueEventTypes.map(type => (
                  <option key={type} value={type}>{type}</option>
                ))}
              </select>
            </div>

            {/* Export Button */}
            <div>
              <button
                onClick={exportEvents}
                className="w-full flex items-center justify-center px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors"
              >
                <Download className="h-4 w-4 mr-2" />
                Export CSV
              </button>
            </div>
          </div>

          {/* Date Range */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Start Date</label>
              <input
                type="date"
                value={dateRange.start}
                onChange={(e) => setDateRange(prev => ({ ...prev, start: e.target.value }))}
                className="w-full border border-gray-300 rounded-md px-3 py-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">End Date</label>
              <input
                type="date"
                value={dateRange.end}
                onChange={(e) => setDateRange(prev => ({ ...prev, end: e.target.value }))}
                className="w-full border border-gray-300 rounded-md px-3 py-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>
        </div>

        {/* Events List and Details */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Events List */}
          <div className="bg-white border border-gray-200 rounded-lg">
            <div className="p-4 border-b border-gray-200">
              <h3 className="text-lg font-medium text-gray-900">
                Events ({filteredEvents.length})
              </h3>
            </div>
            <div className="max-h-96 overflow-y-auto">
              {loading ? (
                <div className="flex items-center justify-center h-32">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                </div>
              ) : filteredEvents.length === 0 ? (
                <div className="p-8 text-center text-gray-500">
                  No events found matching the current filters
                </div>
              ) : (
                <div className="divide-y divide-gray-200">
                  {filteredEvents.map((event) => (
                    <div
                      key={event.id}
                      onClick={() => setSelectedEvent(event)}
                      className={`p-4 cursor-pointer hover:bg-gray-50 transition-colors ${
                        selectedEvent?.id === event.id ? 'bg-blue-50 border-r-4 border-blue-500' : ''
                      }`}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center mb-1">
                            {getEventTypeIcon(event.event_type)}
                            <span className="ml-2 font-medium text-gray-900">{event.event_type}</span>
                            <span className={`ml-2 inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(event.severity)}`}>
                              {event.severity}
                            </span>
                          </div>
                          <p className="text-sm text-gray-600 mb-1">{event.description}</p>
                          <div className="flex items-center text-xs text-gray-500">
                            <Calendar className="h-3 w-3 mr-1" />
                            {new Date(event.timestamp).toLocaleString()}
                            {event.user_id && (
                              <>
                                <span className="mx-2">•</span>
                                <User className="h-3 w-3 mr-1" />
                                {event.user_id}
                              </>
                            )}
                          </div>
                        </div>
                        <Eye className="h-4 w-4 text-gray-400" />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Event Details */}
          <div className="bg-white border border-gray-200 rounded-lg">
            <div className="p-4 border-b border-gray-200">
              <h3 className="text-lg font-medium text-gray-900">Event Details</h3>
            </div>
            <div className="p-4">
              {selectedEvent ? (
                <div className="space-y-4">
                  {/* Basic Info */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Event Type</label>
                      <p className="mt-1 text-sm text-gray-900">{selectedEvent.event_type}</p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Severity</label>
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(selectedEvent.severity)}`}>
                        {selectedEvent.severity}
                      </span>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Timestamp</label>
                      <p className="mt-1 text-sm text-gray-900">
                        {new Date(selectedEvent.timestamp).toLocaleString()}
                      </p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">User ID</label>
                      <p className="mt-1 text-sm text-gray-900">{selectedEvent.user_id || 'System'}</p>
                    </div>
                  </div>

                  {/* Description */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Description</label>
                    <p className="mt-1 text-sm text-gray-900">{selectedEvent.description}</p>
                  </div>

                  {/* Metadata */}
                  {selectedEvent.metadata && Object.keys(selectedEvent.metadata).length > 0 && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Additional Details</label>
                      <div className="bg-gray-50 p-3 rounded-md">
                        <div className="grid grid-cols-1 gap-2 text-sm">
                          {Object.entries(selectedEvent.metadata).map(([key, value]) => (
                            <div key={key} className="flex justify-between">
                              <span className="font-medium text-gray-700">{key}:</span>
                              <span className="text-gray-900 font-mono text-xs break-all">{String(value)}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Event ID */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Event ID</label>
                    <p className="mt-1 text-xs font-mono text-gray-600 bg-gray-50 p-2 rounded">
                      {selectedEvent.id}
                    </p>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <Info className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                  <p>Select an event to view details</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};