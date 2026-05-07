const crypto = require('crypto');

const MEMBERS_LIST_ID = 'VLZT28';

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function verifySignature(rawBody, sigHeader, secret) {
  const timestamp = sigHeader.split(',').find(p => p.startsWith('t=')).slice(2);
  const signature = sigHeader.split(',').find(p => p.startsWith('v1=')).slice(3);
  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${rawBody}`, 'utf8')
    .digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature))) {
    throw new Error('Signature mismatch');
  }
}

async function addMemberToKlaviyo(email, firstName) {
  const KEY = process.env.KLAVIYO_PRIVATE_KEY;
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Klaviyo-API-Key ${KEY}`,
    'revision': '2024-02-15',
  };

  // Upsert profile
  const profileRes = await fetch('https://a.klaviyo.com/api/profiles/', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      data: {
        type: 'profile',
        attributes: { email, first_name: firstName || '' },
      },
    }),
  });

  let profileId;
  if (profileRes.status === 409) {
    const body = await profileRes.json();
    profileId = body?.errors?.[0]?.meta?.duplicate_profile_id;
  } else if (profileRes.ok) {
    const body = await profileRes.json();
    profileId = body?.data?.id;
  } else {
    throw new Error(`Profile upsert failed: ${profileRes.status}`);
  }

  if (!profileId) throw new Error('Could not resolve Klaviyo profile ID');

  // Add profile to members list
  const listRes = await fetch(
    `https://a.klaviyo.com/api/lists/${MEMBERS_LIST_ID}/relationships/profiles/`,
    {
      method: 'POST',
      headers,
      body: JSON.stringify({
        data: [{ type: 'profile', id: profileId }],
      }),
    }
  );

  if (!listRes.ok && listRes.status !== 409) {
    throw new Error(`List enrollment failed: ${listRes.status}`);
  }
}

async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const rawBody = await getRawBody(req);
  const sigHeader = req.headers['stripe-signature'];

  try {
    verifySignature(rawBody.toString(), sigHeader, process.env.STRIPE_WEBHOOK_SECRET);
  } catch {
    return res.status(400).json({ error: 'Invalid webhook signature' });
  }

  const event = JSON.parse(rawBody.toString());

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email = session.customer_details?.email;
    const firstName = session.customer_details?.name?.split(' ')[0] || '';

    if (email) {
      try {
        await addMemberToKlaviyo(email, firstName);
      } catch (err) {
        console.error('Klaviyo enrollment error:', err.message);
        return res.status(500).json({ error: 'Klaviyo enrollment failed' });
      }
    }
  }

  return res.status(200).json({ received: true });
}

handler.config = { api: { bodyParser: false } };

module.exports = handler;
