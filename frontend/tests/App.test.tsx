import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { App } from '../src/App';

describe('AegisOps Frontend Application', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders dashboard title and main structure', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          system: 'AegisOps DevSecOps Platform',
          version: '1.0.0',
          status: 'operational',
          services: {
            api: { status: 'healthy', version: '1.0.0' },
            pythonService: { status: 'healthy', available: true },
          },
          uptimeSeconds: 120,
        }),
      })
    );

    render(<App />);
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument();
    expect(screen.getByText(/System Health & Status/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText(/OPERATIONAL/i)).toBeInTheDocument();
    });
  });

  it('displays connection alert when API fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new Error('Network offline'))
    );

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/Communication Alert:/i)).toBeInTheDocument();
      expect(screen.getByText(/Network offline/i)).toBeInTheDocument();
    });
  });

  it('handles client-side form validation for path traversal', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          system: 'AegisOps',
          status: 'operational',
          services: { api: { status: 'healthy' }, pythonService: { available: true } },
          uptimeSeconds: 10,
        }),
      })
    );

    render(<App />);
    const input = screen.getByPlaceholderText(/e.g. app-container/i);
    const submitBtn = screen.getByText(/Evaluate Security Policy/i);

    fireEvent.change(input, { target: { value: '../../malicious' } });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByText(/path traversal characters are forbidden/i)).toBeInTheDocument();
    });
  });
});
