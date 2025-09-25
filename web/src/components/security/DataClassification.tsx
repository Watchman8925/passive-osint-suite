import React, { useState, useEffect } from 'react';
import { Database, FileText, Lock, Unlock, Eye, EyeOff, AlertTriangle } from 'lucide-react';
import { securityAPI, DataObject, AccessPolicy } from '../../services/securityAPI';

interface DataClassificationProps {
  className?: string;
}

export const DataClassification: React.FC<DataClassificationProps> = ({ className = '' }) => {
  const [dataObjects, setDataObjects] = useState<DataObject[]>([]);
  const [policies, setPolicies] = useState<AccessPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'objects' | 'policies'>('objects');
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [editingObject, setEditingObject] = useState<DataObject | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [objectsData, policiesData] = await Promise.all([
        securityAPI.getDataObjects(),
        securityAPI.getAccessPolicies()
      ]);
      setDataObjects(objectsData);
      setPolicies(policiesData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateObject = async (objectData: Partial<DataObject>) => {
    try {
      await securityAPI.createDataObject(objectData);
      setShowCreateForm(false);
      loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create data object');
    }
  };

  const handleUpdateObject = async (objectId: string, objectData: Partial<DataObject>) => {
    try {
      await securityAPI.updateDataObject(objectId, objectData);
      setEditingObject(null);
      loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update data object');
    }
  };

  const handleDeleteObject = async (objectId: string) => {
    if (!confirm('Are you sure you want to delete this data object?')) return;

    try {
      await securityAPI.deleteDataObject(objectId);
      loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete data object');
    }
  };

  const getClassificationIcon = (classification: string) => {
    switch (classification.toLowerCase()) {
      case 'restricted':
        return <Lock className="h-4 w-4 text-red-600" />;
      case 'confidential':
        return <AlertTriangle className="h-4 w-4 text-orange-600" />;
      case 'internal':
        return <Eye className="h-4 w-4 text-yellow-600" />;
      default:
        return <Unlock className="h-4 w-4 text-green-600" />;
    }
  };

  const getClassificationColor = (classification: string) => {
    switch (classification.toLowerCase()) {
      case 'restricted': return 'text-red-600 bg-red-100';
      case 'confidential': return 'text-orange-600 bg-orange-100';
      case 'internal': return 'text-yellow-600 bg-yellow-100';
      default: return 'text-green-600 bg-green-100';
    }
  };

  if (loading) {
    return (
      <div className={`flex items-center justify-center h-64 ${className}`}>
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center">
          <Database className="h-8 w-8 text-blue-600 mr-3" />
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Data Classification</h1>
            <p className="text-gray-600">Manage data objects and access policies</p>
          </div>
        </div>
        {activeTab === 'objects' && (
          <button
            onClick={() => setShowCreateForm(true)}
            className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <FileText className="h-4 w-4 mr-2" />
            Add Data Object
          </button>
        )}
      </div>

      {/* Error Message */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <span className="text-red-800">{error}</span>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab('objects')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'objects'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Data Objects ({dataObjects.length})
          </button>
          <button
            onClick={() => setActiveTab('policies')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'policies'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Access Policies ({policies.length})
          </button>
        </nav>
      </div>

      {/* Data Objects Tab */}
      {activeTab === 'objects' && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Data Object
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Classification
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Owner
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Created
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Last Modified
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {dataObjects.map((obj) => (
                  <tr key={obj.id}>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <FileText className="h-5 w-5 text-gray-400 mr-3" />
                        <div>
                          <div className="text-sm font-medium text-gray-900">{obj.name}</div>
                          <div className="text-sm text-gray-500">{obj.description}</div>
                          <div className="text-xs text-gray-400">{obj.data_type}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        {getClassificationIcon(obj.classification)}
                        <span className={`ml-2 inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getClassificationColor(obj.classification)}`}>
                          {obj.classification}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {obj.owner_id}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(obj.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(obj.updated_at).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <div className="flex items-center justify-end space-x-2">
                        <button
                          onClick={() => setEditingObject(obj)}
                          className="text-blue-600 hover:text-blue-900"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleDeleteObject(obj.id)}
                          className="text-red-600 hover:text-red-900"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Access Policies Tab */}
      {activeTab === 'policies' && (
        <div className="space-y-4">
          {policies.map((policy) => (
            <div key={policy.id} className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center">
                  <Lock className="h-5 w-5 text-gray-400 mr-3" />
                  <div>
                    <h3 className="text-lg font-medium text-gray-900">{policy.name}</h3>
                    <p className="text-sm text-gray-500">{policy.description}</p>
                  </div>
                </div>
                <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                  policy.is_active ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                }`}>
                  {policy.is_active ? 'Active' : 'Inactive'}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="text-sm font-medium text-gray-700 mb-2">Resource Pattern</h4>
                  <p className="text-sm text-gray-600 font-mono bg-gray-50 p-2 rounded">
                    {policy.resource_pattern}
                  </p>
                </div>

                <div>
                  <h4 className="text-sm font-medium text-gray-700 mb-2">Required Permissions</h4>
                  <div className="flex flex-wrap gap-1">
                    {policy.required_permissions.map((perm) => (
                      <span key={perm} className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800">
                        {perm}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <h4 className="text-sm font-medium text-gray-700 mb-2">Required Roles</h4>
                  <div className="flex flex-wrap gap-1">
                    {policy.required_roles.map((role) => (
                      <span key={role} className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-purple-100 text-purple-800">
                        {role}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <h4 className="text-sm font-medium text-gray-700 mb-2">Minimum Clearance</h4>
                  <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getClassificationColor(policy.min_clearance)}`}>
                    {policy.min_clearance}
                  </span>
                </div>
              </div>

              <div className="mt-4 pt-4 border-t border-gray-200">
                <div className="flex items-center justify-between text-sm text-gray-500">
                  <span>Created: {new Date(policy.created_at).toLocaleString()}</span>
                  <span>Last Modified: {new Date(policy.updated_at).toLocaleString()}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create Data Object Modal */}
      {showCreateForm && (
        <DataObjectForm
          onSubmit={handleCreateObject}
          onCancel={() => setShowCreateForm(false)}
          title="Create Data Object"
        />
      )}

      {/* Edit Data Object Modal */}
      {editingObject && (
        <DataObjectForm
          dataObject={editingObject}
          onSubmit={(data) => handleUpdateObject(editingObject.id, data)}
          onCancel={() => setEditingObject(null)}
          title="Edit Data Object"
        />
      )}
    </div>
  );
};

// Data Object Form Component
interface DataObjectFormProps {
  dataObject?: DataObject;
  onSubmit: (data: Partial<DataObject>) => void;
  onCancel: () => void;
  title: string;
}

const DataObjectForm: React.FC<DataObjectFormProps> = ({ dataObject, onSubmit, onCancel, title }) => {
  const [formData, setFormData] = useState<Partial<DataObject>>({
    name: dataObject?.name || '',
    description: dataObject?.description || '',
    data_type: dataObject?.data_type || '',
    classification: dataObject?.classification || 'public',
    metadata: dataObject?.metadata || {},
    ...dataObject
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
      <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
        <div className="mt-3">
          <h3 className="text-lg font-medium text-gray-900 mb-4">{title}</h3>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">Name</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">Description</label>
              <textarea
                value={formData.description}
                onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
                rows={3}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">Data Type</label>
              <input
                type="text"
                value={formData.data_type}
                onChange={(e) => setFormData(prev => ({ ...prev, data_type: e.target.value }))}
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
                placeholder="e.g., investigation, report, evidence"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">Classification</label>
              <select
                value={formData.classification}
                onChange={(e) => setFormData(prev => ({ ...prev, classification: e.target.value }))}
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
              >
                <option value="public">Public</option>
                <option value="internal">Internal</option>
                <option value="confidential">Confidential</option>
                <option value="restricted">Restricted</option>
              </select>
            </div>

            <div className="flex justify-end space-x-3 pt-4">
              <button
                type="button"
                onClick={onCancel}
                className="px-4 py-2 bg-gray-300 text-gray-700 rounded-lg hover:bg-gray-400 transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                {dataObject ? 'Update' : 'Create'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};