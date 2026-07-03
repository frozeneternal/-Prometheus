export async function getJson(url, options) {
  const response = await fetch(url, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.ok === false) {
    const error = new Error(payload.message || `HTTP ${response.status}`);
    error.payload = payload;
    throw error;
  }
  return payload;
}
