import bcrypt from 'bcryptjs'; import { db } from './server'; import { analyze } from './riskEngine';
(async () => {
  const u = await db.query("INSERT INTO users(name,email,password_hash) VALUES('Demo User','demo@aishield.ai',$1) ON CONFLICT(email) DO UPDATE SET name=excluded.name RETURNING id", [await bcrypt.hash('Demo@12345', 12)]);
  for (const m of ['Your bank account will be blocked today. Verify immediately.', 'Congratulations! You won ₹50,000. Click to claim.', 'Your parcel could not be delivered. Pay ₹25 at http://bit.ly/x', 'Your OTP is 384921.', 'Meeting scheduled for 3 PM.']) {
    const r = analyze('message', m);
    await db.query('INSERT INTO scans(user_id,type,input,risk_score,classification,threat_category,confidence,analysis,recommendations) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)', [u.rows[0].id, 'message', m, r.riskScore, r.classification, r.threatCategory, r.confidence, JSON.stringify(r.analysis), JSON.stringify(r.recommendations)]);
  }
  console.log('Seeded demo@aishield.ai'); process.exit(0);
})();
