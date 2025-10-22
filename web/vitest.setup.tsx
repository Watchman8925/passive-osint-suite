import '@testing-library/jest-dom';
import { render } from '@testing-library/react';
import type { ReactElement } from 'react';
import { AuthProvider } from './src/contexts/AuthContext';

const withProviders = (ui: ReactElement, options?: Parameters<typeof render>[1]) =>
  render(<AuthProvider>{ui}</AuthProvider>, options);

export * from '@testing-library/react';
export { withProviders as render };