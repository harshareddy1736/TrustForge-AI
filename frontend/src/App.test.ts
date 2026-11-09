import { describe, expect, it } from 'vitest'
import { riskBand, safeCvssLabel, severityClass, SEVERITY_LEVELS } from './security'

describe('TrustForge security presentation helpers', () => {
  it('maps all supported severity labels to safe CSS classes', () => {
    expect(SEVERITY_LEVELS).toEqual(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'])
    expect(severityClass('HIGH')).toBe('severity severity-high')
    expect(severityClass('UNKNOWN')).toBe('severity severity-unknown')
  })

  it('maps heuristic scores to transparent risk bands', () => {
    expect(riskBand(0)).toBe('NONE')
    expect(riskBand(10)).toBe('LOW')
    expect(riskBand(25)).toBe('MODERATE')
    expect(riskBand(40)).toBe('HIGH')
    expect(riskBand(85)).toBe('CRITICAL')
  })

  it('formats CVSS only when a valid numeric score is available', () => {
    expect(safeCvssLabel(7.5)).toBe('CVSS 7.5')
    expect(safeCvssLabel(undefined)).toBe('CVSS not available')
    expect(safeCvssLabel(99)).toBe('CVSS not available')
  })
})
