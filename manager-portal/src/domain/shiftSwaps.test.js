import { describe, expect, it } from 'vitest';
import { canReviewSwap, DEFAULT_SWAP_FILTER, SWAP_FILTERS } from './shiftSwaps.js';

describe('shift swap API contract', () => {
  it('opens on swaps that are waiting for manager approval', () => {
    expect(DEFAULT_SWAP_FILTER).toBe('accepted');
  });

  it('uses the backend lifecycle states without legacy pending state', () => {
    expect(SWAP_FILTERS.map((item) => item.value)).toEqual([
      'accepted', 'open', 'approved', 'rejected', 'cancelled', '',
    ]);
  });

  it('allows review only after a guard has volunteered', () => {
    expect(canReviewSwap({ status: 'accepted', volunteer_id: 'guard-2' })).toBe(true);
    expect(canReviewSwap({ status: 'open', volunteer_id: null })).toBe(false);
    expect(canReviewSwap({ status: 'approved', volunteer_id: 'guard-2' })).toBe(false);
  });
});
