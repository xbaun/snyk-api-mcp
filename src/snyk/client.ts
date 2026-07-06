import { env } from '../config.js';

export async function snykGet(
  path: string,
  accept = 'application/vnd.api+json',
) {
  const url = `${env.SNYK_API_BASE}${path}`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `token ${env.SNYK_TOKEN}`,
        Accept: accept,
        'Content-Type': accept,
      },
    });
  } catch (cause) {
    throw new Error(`Snyk API network error\nURL: ${url}`, { cause });
  }

  const text = await response.text();

  if (!response.ok) {
    throw new Error(
      `Snyk API error ${response.status} ${response.statusText}\nURL: ${url}\nResponse: ${text}`,
    );
  }

  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
