import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import { ProvenancePanel } from '../components/ProvenancePanel';

describe('ProvenancePanel', () => {
  it('renders select investigation message without id', () => {
    const { getByText } = render(<ProvenancePanel />);
    expect(getByText(/Select an investigation/i)).toBeTruthy();
  });
});
