export function withdrawalAvailableAt(releasedAt) {
  const date = new Date(releasedAt);
  if (!Number.isFinite(date.getTime())) throw new Error("Invalid payment release date.");
  let remaining = 3;
  while (remaining > 0) {
    date.setUTCDate(date.getUTCDate() + 1);
    if (date.getUTCDay() !== 0 && date.getUTCDay() !== 6) remaining -= 1;
  }
  return date.toISOString();
}
