export const SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const

export function severityClass(severity: string): string {
  const safe = (severity || 'unknown').toLowerCase().replace(/[^a-z]/g, '')
  return `severity severity-${safe || 'unknown'}`
}

export function riskBand(score: number): 'NONE' | 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL' {
  if (score >= 70) return 'CRITICAL'
  if (score >= 40) return 'HIGH'
  if (score >= 20) return 'MODERATE'
  if (score > 0) return 'LOW'
  return 'NONE'
}

export function safeCvssLabel(score?: number | null): string {
  return typeof score === 'number' && Number.isFinite(score) && score >= 0 && score <= 10
    ? `CVSS ${score.toFixed(1)}`
    : 'CVSS not available'
}
