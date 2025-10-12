import { describe, it, expect } from 'vitest';
import {
  formatNlpResponse,
  formatAutopivotResponse,
  FALLBACK_TITLE,
  getErrorMessage,
} from './ChatInterface';

describe('ChatInterface helpers', () => {
  it('formats parsed NLP responses with details', () => {
    const response = formatNlpResponse(
      {
        intent: 'investigate',
        target_type: 'domain',
        target: 'example.com',
        modules: ['domain_recon', 'ssl_cert_fetch'],
        confidence: 0.82,
      },
      'parse'
    );

    expect(response.text).toContain('**Parsed Command**');
    expect(response.text).toContain('`investigate`');
    expect(response.text).toContain('`example.com`');
    expect(response.text).toContain('`domain_recon`');
    expect(response.text).toContain('82.0%');
  });

  it('renders execution success blocks with markdown payload', () => {
    const response = formatNlpResponse(
      {
        status: 'executed',
        parsed: {
          intent: 'investigate',
          target: 'contoso.com',
          modules: ['dns_basic'],
        },
        results: {
          dns_basic: { records: ['ns1.contoso.com'] },
        },
      },
      'execute'
    );

    expect(response.text).toContain('✅ **Command Executed Successfully**');
    expect(response.text).toContain('`dns_basic`');
    expect(response.text).toContain('```json');
    expect(response.text).toContain('ns1.contoso.com');
  });

  it('formats autopivot suggestions into numbered list', () => {
    const response = formatAutopivotResponse({
      pivot_suggestions: [
        {
          target: 'mail.contoso.com',
          target_type: 'domain',
          reason: 'MX record match',
          confidence: 0.91,
          priority: 'high',
          recommended_modules: ['dns_intel'],
        },
      ],
    });

    expect(response.text).toContain('✨ **Autopivot Suggestions**');
    expect(response.text).toContain('1. mail.contoso.com');
    expect(response.text).toContain('91%');
    expect(response.text).toContain('`dns_intel`');
  });

  it('returns fallback title constant', () => {
    expect(FALLBACK_TITLE).toBe('New Conversation');
  });

  it('normalizes axios errors via getErrorMessage', () => {
    const customError = { isAxiosError: true, message: 'boom', response: { data: { detail: 'Forbidden' } } } as any;
    expect(getErrorMessage(customError)).toBe('Forbidden');
    expect(getErrorMessage(new Error('fail'))).toBe('fail');
    expect(getErrorMessage({})).toBe('Unexpected error occurred.');
  });
});
