/**
 * Volume Profile — POC (Point of Control) and Value Area.
 *
 * Each bar's volume is spread evenly over the price bins its high–low range
 * covers. POC = centre of the fullest bin; the Value Area grows from the POC
 * towards the fuller neighbour until it holds 70% of the volume (VAL–VAH).
 * When a feed has no volume (e.g. Yahoo FX) every bar counts 1, which gives
 * the classic TPO / time-at-price profile.
 */
export interface VolumeProfile { poc: number; vah: number; val: number; source: "volume" | "tpo" }

export function calcVolumeProfile(
  highs: number[], lows: number[], closes: number[], volumes?: number[],
  lookback = 100, bins = 30, end = closes.length - 1,
): VolumeProfile | null {
  const start = Math.max(0, end - lookback + 1);
  if (end - start + 1 < 20) return null;
  let lo = Infinity, hi = -Infinity, volSum = 0;
  for (let i = start; i <= end; i++) {
    if (lows[i] < lo) lo = lows[i];
    if (highs[i] > hi) hi = highs[i];
    volSum += volumes?.[i] && volumes[i] > 0 ? volumes[i] : 0;
  }
  if (!(hi > lo)) return null;
  const useVol = volSum > 0;
  const size = (hi - lo) / bins;
  const prof = new Array(bins).fill(0);
  for (let i = start; i <= end; i++) {
    const v = useVol ? Math.max(0, volumes![i] || 0) : 1;
    if (v === 0) continue;
    const a = Math.min(bins - 1, Math.max(0, Math.floor((lows[i] - lo) / size)));
    const b = Math.min(bins - 1, Math.max(0, Math.floor((highs[i] - lo) / size)));
    const share = v / (b - a + 1);
    for (let k = a; k <= b; k++) prof[k] += share;
  }
  let pocBin = 0;
  for (let k = 1; k < bins; k++) if (prof[k] > prof[pocBin]) pocBin = k;
  const total = prof.reduce((s, x) => s + x, 0);
  let lowB = pocBin, highB = pocBin, acc = prof[pocBin];
  while (acc < total * 0.7 && (lowB > 0 || highB < bins - 1)) {
    const up = highB < bins - 1 ? prof[highB + 1] : -1;
    const dn = lowB > 0 ? prof[lowB - 1] : -1;
    if (up >= dn) { highB++; acc += prof[highB]; } else { lowB--; acc += prof[lowB]; }
  }
  return {
    poc: lo + (pocBin + 0.5) * size,
    vah: lo + (highB + 1) * size,
    val: lo + lowB * size,
    source: useVol ? "volume" : "tpo",
  };
}
