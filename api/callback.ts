import { IncomingMessage, ServerResponse } from "http";
import { AuthorizationCode } from "simple-oauth2";
import { config, Provider } from "../lib/config";

export default async (req: IncomingMessage, res: ServerResponse) => {
  const { host } = req.headers;
  const url = new URL(`https://${host}${req.url}`);
  const urlParams = url.searchParams;
  const code = urlParams.get("code");
  const provider = (urlParams.get("provider") || "github") as Provider;

  res.setHeader("Content-Type", "text/html; charset=utf-8");

  try {
    if (!code) throw new Error(`Missing code ${code}`);

    const client = new AuthorizationCode(config(provider));
    const tokenParams = {
      code,
      redirect_uri: `https://${host}/callback?provider=${provider}`,
    };

    const accessToken = await client.getToken(tokenParams);
    const token = accessToken.token["access_token"] as string | undefined;

    if (!token) {
      throw new Error(
        `No access_token from GitHub: ${JSON.stringify(accessToken.token)}`
      );
    }

    const responseBody = renderBody("success", provider, {
      token,
      provider,
    });

    res.statusCode = 200;
    res.end(responseBody);
  } catch (e: unknown) {
    console.error("OAuth callback error:", e);
    const message = e instanceof Error ? e.message : String(e);
    res.statusCode = 200;
    res.end(renderBody("error", provider, { message, provider }));
  }
};

function renderBody(
  status: string,
  provider: string,
  content: Record<string, unknown>
) {
  const payload = JSON.stringify(
    `authorization:${provider}:${status}:${JSON.stringify(content)}`
  );
  const handshake = JSON.stringify(`authorizing:${provider}`);
  return `<!doctype html>
<html>
  <body>
    <script>
      if (window.opener) {
        const receiveMessage = (message) => {
          window.opener.postMessage(${payload}, message.origin);
          window.removeEventListener("message", receiveMessage, false);
        };
        window.addEventListener("message", receiveMessage, false);
        window.opener.postMessage(${handshake}, "*");
      } else {
        document.body.textContent =
          "No opener window found. Please start login from /admin.";
      }
    </script>
  </body>
</html>`;
}
