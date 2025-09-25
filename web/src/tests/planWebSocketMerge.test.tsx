import { describe, it, expect, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import * as apiClient from '../services/apiClientGenerated';
import { usePlan } from '../hooks/useAutonomy';

const mockPlan = {
  investigation_id: 'inv1',
  tasks: [
    { id: 't1', capability_id: 'dns_basic', status: 'pending', depends_on: [], inputs: {} },
    { id: 't2', capability_id: 'ssl_cert_fetch', status: 'pending', depends_on: ['t1'], inputs: {} }
  ]
};

describe('usePlan WebSocket merge', () => {
  it('merges status updates into plan tasks', async () => {
    vi.spyOn(apiClient, 'getPlan').mockResolvedValue(mockPlan);
    // Simulate planTasks from WebSocket
    const planTasks = {
      t1: { id: 't1', capability_id: 'dns_basic', status: 'completed', depends_on: [], inputs: {} },
      t2: { id: 't2', capability_id: 'ssl_cert_fetch', status: 'running', depends_on: ['t1'], inputs: {} }
    };
    // Patch useInvestigationWebSocket to return our planTasks
    vi.mock('../hooks/useWebSocket', () => ({
      useInvestigationWebSocket: () => ({ planTasks })
    }));
    const { result } = renderHook(() => usePlan('inv1'));
    // Wait for hook to update
    await act(async () => {});
    expect(result.current.plan?.tasks[0].status).toBe('completed');
    expect(result.current.plan?.tasks[1].status).toBe('running');
  });
});
