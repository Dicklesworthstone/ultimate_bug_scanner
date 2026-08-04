// Buggy control for GH #73: divisions whose denominators are unguarded
// variables can produce Infinity/NaN and must still be reported.
export function pairwiseRatios(a, b, c, d, e, f, g, h, i, j, k, l, m, n) {
  const r1 = a / b;
  const r2 = a / c;
  const r3 = a / d;
  const r4 = a / e;
  const r5 = a / f;
  const r6 = a / g;
  const r7 = a / h;
  const r8 = a / i;
  const r9 = a / j;
  const r10 = a / k;
  const r11 = a / l;
  const r12 = a / m;
  const r13 = a / n;
  const r14 = b / c;
  const r15 = b / d;
  const r16 = b / e;
  const r17 = b / f;
  const r18 = b / g;
  const r19 = b / h;
  const r20 = b / i;
  const r21 = b / j;
  const r22 = b / k;
  const r23 = b / l;
  const r24 = b / m;
  const r25 = b / n;
  const r26 = c / d;
  const r27 = c / e;
  const r28 = c / f;
  return [
    r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14,
    r15, r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r26, r27, r28,
  ];
}
