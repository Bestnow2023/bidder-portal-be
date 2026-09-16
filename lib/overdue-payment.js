export function overduePaymentAmount(payment, clientId, bidderId, today) {
  if (!payment || payment.status !== "scheduled" || payment.paymentType === "withdrawal" ||
      payment.clientId !== clientId || payment.userId !== bidderId ||
      !/^\d{4}-\d{2}-\d{2}$/.test(payment.scheduledDate || "") || payment.scheduledDate >= today) {
    throw new Error("Select an unpaid payment whose due date has passed.");
  }
  const amount = Number(payment.amount);
  if (!Number.isFinite(amount) || amount <= 0) throw new Error("The overdue payment must have a positive amount.");
  return Math.round(amount * 100) / 100;
}
