import React, { useState } from 'react';
import { useForm, useFieldArray } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useMutation } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  XMarkIcon, 
  PlusIcon, 
  TrashIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

import { InvestigationType, Priority } from '../../types/investigation';
import { investigationApi } from '../../services/api';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Textarea } from '../ui/Textarea';
import { Select } from '../ui/Select';
import { Modal } from '../ui/Modal';
import { Badge } from '../ui/Badge';

interface CreateInvestigationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

const investigationSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100, 'Name too long'),
  description: z.string().min(1, 'Description is required').max(1000, 'Description too long'),
  investigation_type: z.nativeEnum(InvestigationType),
  targets: z.array(z.string().min(1, 'Target cannot be empty')).min(1, 'At least one target is required'),
  priority: z.nativeEnum(Priority),
  deadline: z.string().optional(),
  tags: z.array(z.string()).optional(),
  analyst: z.string().min(1, 'Analyst name is required'),
  organization: z.string().optional(),
  configuration: z.object({
    include_subdomains: z.boolean().optional(),
    deep_scan: z.boolean().optional(),
    threat_intelligence: z.boolean().optional(),
    social_media: z.boolean().optional(),
    dark_web: z.boolean().optional(),
    max_depth: z.number().min(1).max(10).optional(),
    timeout: z.number().min(30).max(3600).optional()
  }).optional()
});

type InvestigationFormData = z.infer<typeof investigationSchema>;

const investigationTypes = [
  { value: InvestigationType.DOMAIN, label: 'Domain Investigation', description: 'Analyze domains, subdomains, and related infrastructure' },
  { value: InvestigationType.IP, label: 'IP Address Investigation', description: 'Investigate IP addresses and network information' },
  { value: InvestigationType.EMAIL, label: 'Email Investigation', description: 'Research email addresses and associated accounts' },
  { value: InvestigationType.PERSON, label: 'Person Investigation', description: 'Investigate individuals across multiple platforms' },
  { value: InvestigationType.COMPANY, label: 'Company Investigation', description: 'Research companies and organizations' },
  { value: InvestigationType.PHONE, label: 'Phone Investigation', description: 'Investigate phone numbers and telecom data' },
  { value: InvestigationType.CRYPTO, label: 'Cryptocurrency Investigation', description: 'Analyze cryptocurrency addresses and transactions' },
  { value: InvestigationType.MIXED, label: 'Mixed Investigation', description: 'Multi-target investigation with various data types' }
];

const priorities = [
  { value: Priority.LOW, label: 'Low', color: 'bg-gray-100 text-gray-800' },
  { value: Priority.MEDIUM, label: 'Medium', color: 'bg-blue-100 text-blue-800' },
  { value: Priority.HIGH, label: 'High', color: 'bg-orange-100 text-orange-800' },
  { value: Priority.CRITICAL, label: 'Critical', color: 'bg-red-100 text-red-800' }
];

export default function CreateInvestigationModal({ isOpen, onClose, onSuccess }: CreateInvestigationModalProps) {
  const [step, setStep] = useState(1);
  const [selectedType, setSelectedType] = useState<InvestigationType | null>(null);

  const {
    register,
    control,
    handleSubmit,
    formState: { errors },
    watch,
    setValue,
    reset,
    getValues
  } = useForm<InvestigationFormData>({
    resolver: zodResolver(investigationSchema),
    defaultValues: {
      priority: Priority.MEDIUM,
      analyst: 'AI Assistant',
      targets: [''],
      tags: [],
      configuration: {
        include_subdomains: true,
        deep_scan: false,
        threat_intelligence: true,
        social_media: false,
        dark_web: false,
        max_depth: 3,
        timeout: 300
      }
    }
  });

  const { fields: targetFields, append: appendTarget, remove: removeTarget } = useFieldArray<any>({
    control: control as any,
    name: 'targets'
  });

  const { fields: tagFields, append: appendTag, remove: removeTag } = useFieldArray<any>({
    control: control as any,
    name: 'tags'
  });

  const createMutation = useMutation({
    mutationFn: investigationApi.createInvestigation,
    onSuccess: () => {
      toast.success('Investigation created successfully');
      reset();
      setStep(1);
      setSelectedType(null);
      onSuccess();
    },
    onError: (error: any) => {
      toast.error(`Failed to create investigation: ${error.message}`);
    }
  });

  const investigationType = watch('investigation_type');

  const handleClose = () => {
    reset();
    setStep(1);
    setSelectedType(null);
    onClose();
  };

  const onSubmit = (data: InvestigationFormData) => {
    const cleanData = {
      name: data.name,
      description: data.description,
      investigation_type: data.investigation_type,
      targets: data.targets.filter(t => t.trim() !== ''),
      analyst: data.analyst || undefined,
      organization: data.organization || undefined,
      priority: data.priority,
      deadline: data.deadline ? new Date(data.deadline).toISOString() : undefined,
      tags: data.tags?.filter(tag => tag.trim() !== '') || [],
      configuration: data.configuration
    };
    createMutation.mutate(cleanData);
  };

  const nextStep = () => {
    if (step < 3) setStep(step + 1);
  };

  const prevStep = () => {
    if (step > 1) setStep(step - 1);
  };

  const getStepTitle = () => {
    switch (step) {
      case 1: return 'Investigation Type';
      case 2: return 'Basic Information';
      case 3: return 'Configuration';
      default: return 'Create Investigation';
    }
  };

  const isStepValid = () => {
    switch (step) {
      case 1:
        return !!investigationType;
      case 2:
        const values = getValues();
        return values.name && values.description && values.targets.some(t => t.trim() !== '');
      case 3:
        return true;
      default:
        return false;
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={handleClose} size="lg">
      <div className="p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">Create New Investigation</h2>
            <p className="text-sm text-gray-600 mt-1">Step {step} of 3: {getStepTitle()}</p>
          </div>
          <button
            onClick={handleClose}
            className="text-gray-400 hover:text-gray-600"
          >
            <XMarkIcon className="h-6 w-6" />
          </button>
        </div>

        {/* Progress Bar */}
        <div className="mb-8">
          <div className="flex items-center">
            {[1, 2, 3].map((stepNumber) => (
              <React.Fragment key={stepNumber}>
                <div className={`flex items-center justify-center w-8 h-8 rounded-full text-sm font-medium ${
                  stepNumber < step ? 'bg-blue-600 text-white' :
                  stepNumber === step ? 'bg-blue-100 text-blue-600 border-2 border-blue-600' :
                  'bg-gray-100 text-gray-400'
                }`}>
                  {stepNumber}
                </div>
                {stepNumber < 3 && (
                  <div className={`flex-1 h-1 mx-4 ${
                    stepNumber < step ? 'bg-blue-600' : 'bg-gray-200'
                  }`} />
                )}
              </React.Fragment>
            ))}
          </div>
        </div>

        <form onSubmit={handleSubmit(onSubmit)}>
          <AnimatePresence mode="wait">
            {step === 1 && (
              <motion.div
                key="step1"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="space-y-4"
              >
                <h3 className="text-lg font-medium text-gray-900 mb-4">
                  Select Investigation Type
                </h3>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {investigationTypes.map((type) => (
                    <label
                      key={type.value}
                      className={`cursor-pointer rounded-lg border-2 p-4 hover:border-blue-300 transition-colors ${
                        investigationType === type.value
                          ? 'border-blue-500 bg-blue-50'
                          : 'border-gray-200'
                      }`}
                    >
                      <input
                        type="radio"
                        value={type.value}
                        {...register('investigation_type')}
                        className="sr-only"
                      />
                      <div>
                        <h4 className="font-medium text-gray-900">{type.label}</h4>
                        <p className="text-sm text-gray-600 mt-1">{type.description}</p>
                      </div>
                    </label>
                  ))}
                </div>
                
                {errors.investigation_type && (
                  <p className="text-sm text-red-600">{errors.investigation_type.message}</p>
                )}
              </motion.div>
            )}

            {step === 2 && (
              <motion.div
                key="step2"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="space-y-6"
              >
                <h3 className="text-lg font-medium text-gray-900 mb-4">
                  Basic Information
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Input
                      label="Investigation Name"
                      {...register('name')}
                      error={errors.name?.message}
                      placeholder="Enter investigation name"
                    />
                  </div>
                  
                  <div>
                    <Select
                      label="Priority"
                      {...register('priority')}
                      error={errors.priority?.message}
                    >
                      {priorities.map((priority) => (
                        <option key={priority.value} value={priority.value}>
                          {priority.label}
                        </option>
                      ))}
                    </Select>
                  </div>
                </div>

                <div>
                  <Textarea
                    label="Description"
                    {...register('description')}
                    error={errors.description?.message}
                    placeholder="Describe the purpose and scope of this investigation"
                    rows={3}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Investigation Targets
                  </label>
                  <div className="space-y-2">
                    {targetFields.map((field, index) => (
                      <div key={field.id} className="flex items-center space-x-2">
                        <Input
                          {...register(`targets.${index}`)}
                          placeholder="Enter target (domain, IP, email, etc.)"
                          className="flex-1"
                        />
                        {targetFields.length > 1 && (
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() => removeTarget(index)}
                          >
                            <TrashIcon className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    ))}
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => appendTarget('')}
                      className="flex items-center"
                    >
                      <PlusIcon className="h-4 w-4 mr-1" />
                      Add Target
                    </Button>
                  </div>
                  {errors.targets && (
                    <p className="text-sm text-red-600 mt-1">{errors.targets.message}</p>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Input
                      label="Analyst"
                      {...register('analyst')}
                      error={errors.analyst?.message}
                      placeholder="Analyst name"
                    />
                  </div>
                  
                  <div>
                    <Input
                      label="Deadline (Optional)"
                      type="datetime-local"
                      {...register('deadline')}
                      error={errors.deadline?.message}
                    />
                  </div>
                </div>
              </motion.div>
            )}

            {step === 3 && (
              <motion.div
                key="step3"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="space-y-6"
              >
                <h3 className="text-lg font-medium text-gray-900 mb-4">
                  Investigation Configuration
                </h3>

                <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                  <div className="flex">
                    <InformationCircleIcon className="h-5 w-5 text-blue-400 mt-0.5" />
                    <div className="ml-3">
                      <h4 className="text-sm font-medium text-blue-800">Configuration Options</h4>
                      <p className="text-sm text-blue-700 mt-1">
                        These settings control how the investigation will be conducted. You can modify them later.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <h4 className="font-medium text-gray-900">Scope Settings</h4>
                    
                    <label className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        {...register('configuration.include_subdomains')}
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                      />
                      <span className="text-sm text-gray-700">Include subdomains</span>
                    </label>
                    
                    <label className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        {...register('configuration.deep_scan')}
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                      />
                      <span className="text-sm text-gray-700">Deep scan (slower, more comprehensive)</span>
                    </label>
                    
                    <label className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        {...register('configuration.threat_intelligence')}
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                      />
                      <span className="text-sm text-gray-700">Threat intelligence lookup</span>
                    </label>
                  </div>

                  <div className="space-y-4">
                    <h4 className="font-medium text-gray-900">Advanced Options</h4>
                    
                    <label className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        {...register('configuration.social_media')}
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                      />
                      <span className="text-sm text-gray-700">Social media search</span>
                    </label>
                    
                    <label className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        {...register('configuration.dark_web')}
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                      />
                      <span className="text-sm text-gray-700">Dark web monitoring</span>
                    </label>
                    
                    <div>
                      <Input
                        label="Max Depth"
                        type="number"
                        min="1"
                        max="10"
                        {...register('configuration.max_depth', { valueAsNumber: true })}
                        placeholder="3"
                      />
                    </div>
                    
                    <div>
                      <Input
                        label="Timeout (seconds)"
                        type="number"
                        min="30"
                        max="3600"
                        {...register('configuration.timeout', { valueAsNumber: true })}
                        placeholder="300"
                      />
                    </div>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Footer */}
          <div className="flex items-center justify-between mt-8 pt-6 border-t border-gray-200">
            <Button
              type="button"
              variant="outline"
              onClick={prevStep}
              disabled={step === 1}
            >
              Previous
            </Button>
            
            <div className="flex items-center space-x-3">
              <Button
                type="button"
                variant="outline"
                onClick={handleClose}
              >
                Cancel
              </Button>
              
              {step < 3 ? (
                <Button
                  type="button"
                  onClick={nextStep}
                  disabled={!isStepValid()}
                >
                  Next
                </Button>
              ) : (
                <Button
                  type="submit"
                  disabled={createMutation.isPending || !isStepValid()}
                  className="bg-blue-600 hover:bg-blue-700"
                >
                  {createMutation.isPending ? 'Creating...' : 'Create Investigation'}
                </Button>
              )}
            </div>
          </div>
        </form>
      </div>
    </Modal>
  );
}