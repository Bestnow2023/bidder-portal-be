export function approvedClientWorkFilter(clientId, userId, contractIds, periodStart, periodEnd) {
  return {
    userId,
    workDate: { $gte: periodStart, $lte: periodEnd },
    reviewStatus: "approved",
    $or: [
      { contractId: { $in: contractIds } },
      { contractId: { $in: [null, ""] }, reviewedByUserId: clientId },
    ],
  };
}
