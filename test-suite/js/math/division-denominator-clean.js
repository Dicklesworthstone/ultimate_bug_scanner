// Clean control for GH #73: constant non-zero denominators (/2, /100,
// Math.PI) and `(x || 1)` guarded divisors can never divide by zero, so a file
// full of them must not raise the division warning no matter how large it is.
export function summarize(samples, total) {
  const half1 = samples[0] / 2;
  const half2 = samples[1] / 2;
  const half3 = samples[2] / 2;
  const half4 = samples[3] / 2;
  const half5 = samples[4] / 2;
  const half6 = samples[5] / 2;
  const half7 = samples[6] / 2;
  const half8 = samples[7] / 2;
  const half9 = samples[8] / 2;
  const half10 = samples[9] / 2;
  const half11 = samples[10] / 2;
  const half12 = samples[11] / 2;
  const half13 = samples[12] / 2;
  const half14 = samples[13] / 2;
  const pct1 = samples[0] / 100;
  const pct2 = samples[1] / 100;
  const pct3 = samples[2] / 100;
  const pct4 = samples[3] / 100;
  const pct5 = samples[4] / 100;
  const pct6 = samples[5] / 100;
  const pct7 = samples[6] / 100;
  const pct8 = samples[7] / 100;
  const pct9 = samples[8] / 100;
  const pct10 = samples[9] / 100;
  const pct11 = samples[10] / 100;
  const pct12 = samples[11] / 100;
  const radians = samples[12] / Math.PI;
  const scaled = samples[13] / 0.5;
  const share = samples[14] / (total || 1);
  return [
    half1, half2, half3, half4, half5, half6, half7, half8, half9, half10,
    half11, half12, half13, half14, pct1, pct2, pct3, pct4, pct5, pct6,
    pct7, pct8, pct9, pct10, pct11, pct12, radians, scaled, share,
  ];
}
