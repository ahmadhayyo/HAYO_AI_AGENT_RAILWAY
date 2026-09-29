/**
 * When does a weights verdict (± liquidity trap) become a SENT signal?
 * Shared by the live bot and the recent-data backtest so both apply the exact
 * same rule.
 *
 * Minimum grade (env WEIGHTS_MIN_GRADE, default "A" — fewer, stronger signals):
 *   A: weights p ≥ 0.58 / ≤ 0.42   → 57.1% (fast) / 56.4% (scalp) out-of-sample 2019
 *   B: weights p ≥ 0.56 / ≤ 0.44   → 55.4% / 55.7%
 * Liquidity trap (1m "fast" model only) needs the weights model to lean the
 * same way. Research, OANDA 1m, 6 instruments, 10 bars:
 *   agreement ≥ 0.53 → 55.7% (2018) / 55.8% (2019)
 *   agreement ≥ 0.56 → 57.3% (2018) / 60.4% (2019)   ← grade-A quality
 */
export type MinGrade = "A" | "B";

export const WEIGHTS_MIN_GRADE: MinGrade = (process.env.WEIGHTS_MIN_GRADE ?? "A").trim().toUpperCase() === "B" ? "B" : "A";

export const TRAP_POLICY: Record<MinGrade, { minP: number; oos2018: number; oos2019: number }> = {
  A: { minP: 0.56, oos2018: 57.3, oos2019: 60.4 },
  B: { minP: 0.53, oos2018: 55.7, oos2019: 55.8 },
};

export interface SignalDecision { mode: "weights" | "trap"; dir: "BUY" | "SELL" }

/**
 * @param v     weights verdict (p = P(up), grade from weightedVerdict)
 * @param trap  liquidity trap on the newest closed bar, or null
 */
export function decideSignal(
  v: { p: number; grade: "A" | "B" | "-" },
  trap: { dir: "BUY" | "SELL" } | null,
  minGrade: MinGrade = WEIGHTS_MIN_GRADE,
): SignalDecision | null {
  const gradeOk = minGrade === "A" ? v.grade === "A" : v.grade !== "-";
  if (gradeOk) return { mode: "weights", dir: v.p > 0.5 ? "BUY" : "SELL" };
  if (trap && trapAgreement(v.p, trap.dir) >= TRAP_POLICY[minGrade].minP) return { mode: "trap", dir: trap.dir };
  return null;
}

/** Weights-model probability in the trap's direction. */
export function trapAgreement(p: number, dir: "BUY" | "SELL"): number {
  return dir === "BUY" ? p : 1 - p;
}
