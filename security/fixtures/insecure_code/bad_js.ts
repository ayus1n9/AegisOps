// Synthetic insecure TypeScript fixture for Semgrep scanner verification only
export function executeDynamicCode(userPayload: string) {
  // Intentional Semgrep trigger
  return eval(userPayload);
}
