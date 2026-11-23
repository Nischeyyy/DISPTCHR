export const DEFAULT_SWAP_FILTER = 'accepted';

export const SWAP_FILTERS = [
  { value: 'accepted', label: 'Awaiting approval' },
  { value: 'open', label: 'Awaiting volunteer' },
  { value: 'approved', label: 'Approved' },
  { value: 'rejected', label: 'Rejected' },
  { value: 'cancelled', label: 'Cancelled' },
  { value: '', label: 'All' },
];

export function canReviewSwap(swap) {
  return swap?.status === 'accepted' && Boolean(swap.volunteer_id);
}
