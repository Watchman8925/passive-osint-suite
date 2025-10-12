import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import React from 'react';
import { describe, expect, beforeEach, test, vi } from 'vitest';

const mocks = vi.hoisted(() => {
  const mockGet = vi.fn();
  const mockPost = vi.fn();
  const mockDelete = vi.fn();
  const axiosInstance = {
    get: mockGet,
    post: mockPost,
    delete: mockDelete,
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  };
  return { mockGet, mockPost, mockDelete, axiosInstance };
});

vi.mock('react-hot-toast', () => {
  const toast = Object.assign(vi.fn(), {
    success: vi.fn(),
    error: vi.fn(),
    loading: vi.fn(),
    dismiss: vi.fn(),
  });
  return { __esModule: true, default: toast };
});

vi.mock('axios', () => ({
  __esModule: true,
  default: {
    create: vi.fn(() => mocks.axiosInstance),
    isAxiosError: (error: any) => Boolean(error?.isAxiosError),
  },
  create: vi.fn(() => mocks.axiosInstance),
  isAxiosError: (error: any) => Boolean(error?.isAxiosError),
  AxiosError: class {},
}));

import { ChatInterface } from './ChatInterface';

describe('ChatInterface', () => {
  beforeEach(() => {
    mocks.mockGet.mockReset();
    mocks.mockPost.mockReset();
    mocks.mockDelete.mockReset();
  });

  test('creates a conversation and renders assistant response', async () => {
    mocks.mockGet.mockResolvedValueOnce({ data: { conversations: [] } });
    mocks.mockGet.mockResolvedValueOnce({ data: { messages: [] } });

    mocks.mockPost
      .mockResolvedValueOnce({
        data: {
          conversation_id: 'conv-1',
          title: 'Investigation Chat',
          created_at: '2025-10-12T10:00:00Z',
        },
      })
      .mockResolvedValueOnce({ data: { message_id: 'msg-user-1' } })
      .mockResolvedValueOnce({
        data: {
          status: 'executed',
          parsed: {
            intent: 'investigate',
            target: 'example.com',
            modules: ['domain_recon'],
            confidence: 0.9,
          },
          results: {},
        },
      })
      .mockResolvedValueOnce({ data: { message_id: 'msg-assistant-1' } });

    render(<ChatInterface apiUrl="http://localhost:8000" />);

    const createButton = await screen.findByRole('button', { name: /create conversation/i });
    fireEvent.click(createButton);
    await waitFor(() =>
      expect(mocks.mockPost).toHaveBeenCalledWith('/api/chat/conversations', expect.any(Object))
    );
    const input = screen.getByPlaceholderText(/describe what you want to investigate/i);
    fireEvent.change(input, { target: { value: 'Investigate example.com' } });

    const sendButton = screen.getByRole('button', { name: /send/i });
    fireEvent.click(sendButton);

    await waitFor(() => expect(mocks.mockPost).toHaveBeenCalledWith('/api/nlp/execute', expect.any(Object)));

    await screen.findByText(/Command Executed Successfully/i);
    expect(screen.getByText('Investigate example.com')).toBeInTheDocument();
  });

  test('calls autopivot when enabled and investigation provided', async () => {
    mocks.mockGet.mockResolvedValueOnce({ data: { conversations: [] } });
    mocks.mockGet.mockResolvedValueOnce({ data: { messages: [] } });

    mocks.mockPost
      .mockResolvedValueOnce({
        data: {
          conversation_id: 'conv-2',
          title: 'Pivot Run',
          created_at: '2025-10-12T11:00:00Z',
        },
      })
      .mockResolvedValueOnce({ data: { message_id: 'msg-user-2' } })
      .mockResolvedValueOnce({
        data: {
          status: 'executed',
          parsed: {
            intent: 'investigate',
            target: 'contoso.com',
            modules: ['domain_recon'],
            confidence: 0.92,
          },
          results: {},
        },
      })
      .mockResolvedValueOnce({ data: { message_id: 'msg-assistant-2' } })
      .mockResolvedValueOnce({
        data: {
          pivot_suggestions: [
            {
              target: 'mail.contoso.com',
              target_type: 'domain',
              reason: 'Related MX record discovered',
              confidence: 0.85,
              priority: 'high',
              recommended_modules: ['dns_intel'],
            },
          ],
        },
      })
      .mockResolvedValueOnce({ data: { message_id: 'msg-autopivot-1' } });

    render(<ChatInterface apiUrl="http://localhost:8000" investigationId="inv-123" />);

    const createButton = await screen.findByRole('button', { name: /create conversation/i });
    fireEvent.click(createButton);
    await waitFor(() =>
      expect(mocks.mockPost).toHaveBeenCalledWith('/api/chat/conversations', expect.any(Object))
    );
    const autopivotToggle = screen.getByLabelText(/autopivot/i);
    fireEvent.click(autopivotToggle);

    const input = screen.getByPlaceholderText(/describe what you want to investigate/i);
    fireEvent.change(input, { target: { value: 'Investigate contoso.com' } });

    const sendButton = screen.getByRole('button', { name: /send/i });
    fireEvent.click(sendButton);

    await waitFor(() =>
      expect(mocks.mockPost).toHaveBeenCalledWith(
        '/api/autopivot/suggest',
        expect.objectContaining({ investigation_id: 'inv-123', max_pivots: 5 })
      )
    );

    await screen.findByText(/Autopivot Suggestions/i);
    expect(screen.getByText(/mail.contoso.com/i)).toBeInTheDocument();
  });
});
