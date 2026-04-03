export async function onRequestPost(context) {
  const { request, env } = context;
  const db = env.DB;

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Invalid request' }, { status: 400 });
  }

  const { apiKey, action } = body;
  if (!apiKey) {
    return Response.json({ error: 'API key required' }, { status: 400 });
  }

  const month = new Date().toISOString().slice(0, 7); // YYYY-MM

  await db
    .prepare(
      `INSERT INTO usage (api_key, month, count) VALUES (?, ?, 1)
       ON CONFLICT(api_key, month) DO UPDATE SET count = count + 1`
    )
    .bind(apiKey, month)
    .run();

  return Response.json({ recorded: true });
}
