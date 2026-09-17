const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);

export function paymentReceivedEmail({ name, clientName, amount, paymentId, periodStart, periodEnd, availableAt, baseUrl }) {
  const url = new URL("/payments", baseUrl);
  if (!["https:", "http:"].includes(url.protocol)) throw new Error("Invalid portal URL.");
  const total = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(amount);
  const available = new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(new Date(availableAt)) + " UTC";
  const period = periodStart && periodEnd ? `${periodStart} to ${periodEnd}` : "See payment details";
  const subject = `You received ${total} | Bidder Portal`;
  const text = `Hi ${name || "there"},\n\nYou received ${total} from ${clientName || "your client"}. The full amount has been added to your Bidder Portal money-credit balance.\n\nWork period: ${period}\nPayment ID: ${paymentId}\nAvailable to withdraw: ${available}\n\nNew payments have a 3-business-day hold (Monday-Friday). This is a balance credit, not a transfer to your external wallet.\n\nView your payment: ${url.href}\n\nBidder Portal by Digniware LLC`;
  const row = (label, value) => `<tr><td style="padding:13px 0;border-bottom:1px solid #e4e9ed;color:#607078;font-size:13px;vertical-align:top">${label}</td><td align="right" style="padding:13px 0 13px 18px;border-bottom:1px solid #e4e9ed;color:#182c30;font-size:13px;word-break:break-word">${escapeHtml(value)}</td></tr>`;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(subject)}</title></head><body style="margin:0;background:#f2f5f7;font-family:Arial,Helvetica,sans-serif;color:#182c30">
  <div style="display:none;max-height:0;overflow:hidden">${escapeHtml(total)} has been added to your balance. Your payment details are inside.</div>
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td align="center" style="padding:32px 12px">
  <table role="presentation" width="560" cellspacing="0" cellpadding="0" style="width:100%;max-width:560px;background:#ffffff;border:1px solid #e0e7eb;border-radius:8px;overflow:hidden">
  <tr><td style="padding:25px 28px;border-top:5px solid #0f766e;border-bottom:1px solid #e4e9ed"><strong style="font-size:18px">Bidder Portal</strong><br><span style="font-size:12px;color:#607078">BY DIGNIWARE LLC</span></td></tr>
  <tr><td style="padding:32px 28px 12px"><span style="font-size:12px;color:#0f766e;font-weight:bold">PAYMENT RECEIVED</span><h1 style="font-size:28px;line-height:1.25;margin:12px 0">Your work has been paid.</h1><p style="font-size:15px;line-height:1.7;color:#52636a;margin:0">Hi ${escapeHtml(name || "there")},<br>${escapeHtml(clientName || "Your client")} has paid you. The full amount is now in your money-credit balance.</p></td></tr>
  <tr><td style="padding:16px 28px"><div style="background:#eff9f5;border-left:4px solid #0f766e;padding:22px"><div style="font-size:12px;color:#52636a">AMOUNT CREDITED</div><div style="font-size:36px;font-weight:bold;line-height:1.3;margin-top:6px">${escapeHtml(total)}</div></div></td></tr>
  <tr><td style="padding:0 28px"><table width="100%" cellspacing="0" cellpadding="0">${row("Client", clientName || "Your client")}${row("Work period", period)}${row("Payment ID", paymentId)}${row("Available to withdraw", available)}</table></td></tr>
  <tr><td style="padding:24px 28px"><p style="font-size:13px;line-height:1.6;color:#607078;margin:0 0 24px">Payments become available to withdraw after 3 business days, Monday-Friday. This receipt confirms a credit to your portal balance, not a transfer to your external wallet.</p><a href="${escapeHtml(url.href)}" style="display:inline-block;background:#0f766e;color:#ffffff;padding:14px 24px;border-radius:6px;text-decoration:none;font-size:14px;font-weight:bold">View payment</a></td></tr>
  <tr><td style="padding:22px 28px;background:#f8fafb;border-top:1px solid #e4e9ed;font-size:12px;line-height:1.7;color:#607078">Bidder Portal by Digniware LLC<br>This is an automatic payment receipt. Need help? Open Support Center from your portal.</td></tr>
  </table></td></tr></table></body></html>`;
  return { subject, text, html };
}
