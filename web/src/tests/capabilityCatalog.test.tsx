import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import { CapabilityCatalog } from '../components/CapabilityCatalog';

// This is a placeholder snapshot-ish test. Real test would mock hook.
describe('CapabilityCatalog', () => {
  it('renders loading initially (mocked empty state)', () => {
    // Without provider/mocking the hook will attempt fetch; keep minimal.
    const { getByText } = render(<CapabilityCatalog />);
    expect(getByText(/Loading capabilities/i)).toBeTruthy();
  });
});
