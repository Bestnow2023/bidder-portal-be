const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);

export function accountEmail({ kind, name, actionUrl, expiresInMs }) {
  if (!["password_reset", "email_verification"].includes(kind)) throw new Error("Unknown account email.");
  const url = new URL(actionUrl);
  if (!["https:", "http:"].includes(url.protocol)) throw new Error("Invalid account link.");
  const reset = kind === "password_reset";
  const action = reset ? "Reset password" : "Verify email address";
  const title = reset ? "A fresh start for your password." : "Welcome to Bidder Portal.";
  const subject = reset ? "Reset your Bidder Portal password" : "Verify your Bidder Portal email";
  const intro = reset ? "We received a request to reset your password. Choose a new password using the secure link below." : "Thanks for joining us. Confirm your email address to continue setting up your account.";
  const note = reset ? "If you did not request this, you can ignore this email. Your password will stay the same." : "If you did not create a Bidder Portal account, you can ignore this email.";
  const hours = expiresInMs / 3600000;
  if (!Number.isFinite(hours) || hours <= 0) throw new Error("Invalid link expiry.");
  const expiry = `${hours} ${hours === 1 ? "hour" : "hours"}`;
  const text = `Hi ${name || "there"},\n\n${intro}\n\n${action}: ${url.href}\n\nThis link expires in ${expiry} and can be used once.\n\n${note}\n\nBidder Portal by Digniware LLC`;
  const safeUrl = escapeHtml(url.href);
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(subject)}</title></head>
  <body style="margin:0;background:#f2f5f7;font-family:Arial,Helvetica,sans-serif;color:#182c30">
  <div style="display:none;max-height:0;overflow:hidden">${action}. Your secure link expires in ${expiry}.</div>
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td align="center" style="padding:32px 12px">
  <table role="presentation" width="560" cellspacing="0" cellpadding="0" style="width:100%;max-width:560px;background:#ffffff;border:1px solid #e0e7eb;border-radius:8px;overflow:hidden">
  <tr><td style="padding:25px 28px;border-top:5px solid #0f766e;border-bottom:1px solid #e4e9ed"><strong style="font-size:18px">Bidder Portal</strong><br><span style="font-size:12px;color:#607078">BY DIGNIWARE LLC</span></td></tr>
  <tr><td style="padding:32px 28px 20px"><span style="font-size:12px;font-weight:bold;color:#0f766e">${reset ? "ACCOUNT SECURITY" : "ONE MORE STEP"}</span><h1 style="font-size:28px;line-height:1.25;margin:12px 0 20px">${title}</h1><p style="font-size:15px;line-height:1.7;color:#52636a;margin:0">Hi ${escapeHtml(name || "there")},<br>${intro}</p></td></tr>
  <tr><td style="padding:4px 28px 28px"><table role="presentation" cellspacing="0" cellpadding="0"><tr><td bgcolor="#0f766e" style="border-radius:6px"><a href="${safeUrl}" style="display:inline-block;padding:16px 26px;border:1px solid #0f766e;border-radius:6px;font-size:15px;font-weight:bold;color:#ffffff;text-decoration:none">${action}</a></td></tr></table></td></tr>
  <tr><td style="padding:0 28px 24px"><div style="background:#eff9f5;border-left:4px solid #0f766e;padding:16px 18px;font-size:13px;line-height:1.6">This link expires in <strong>${expiry}</strong> and can be used once.</div><p style="font-size:13px;line-height:1.7;color:#607078;margin:20px 0 0">${note}</p></td></tr>
  <tr><td style="padding:0 28px 28px"><p style="font-size:12px;line-height:1.6;color:#607078;margin:0 0 8px">Button not working? Copy this link into your browser:</p><a href="${safeUrl}" style="font-size:12px;line-height:1.7;color:#0f766e;word-break:break-all;overflow-wrap:anywhere">${safeUrl}</a></td></tr>
  <tr><td style="padding:22px 28px;background:#f8fafb;border-top:1px solid #e4e9ed;font-size:12px;line-height:1.7;color:#607078">Bidder Portal by Digniware LLC<br>${reset ? "Keep this link private. We will never ask you to share your password." : "Email verification confirms your address. Account access may still require approval."}</td></tr>
  </table></td></tr></table></body></html>`;
  return { subject, text, html };
}
