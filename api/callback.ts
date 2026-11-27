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
  const statusText = JSON.stringify(
    status === "success"
      ? "Login successful! Returning to CMS..."
      : `Authentication error: ${String(content.message || "Unknown error")}`
  );
  return `<!doctype html>
<html>
  <body style="font-family: system-ui, sans-serif; padding: 24px; color: #28231E;">
    <p id="status"></p>
    <script>
      document.getElementById("status").textContent = ${statusText};
      if (window.opener) {
        const receiveMessage = (message) => {
          if (message.data !== ${handshake}) return;
          window.opener.postMessage(${payload}, message.origin);
          window.removeEventListener("message", receiveMessage, false);
          if (${JSON.stringify(status)} === "success") {
            setTimeout(() => window.close(), 1000);
          }
        };
        window.addEventListener("message", receiveMessage, false);
        window.opener.postMessage(${handshake}, "*");
      } else {
        document.getElementById("status").textContent =
          "No opener window found. Please start login from /admin.";
      }
    </script>
  </body>
</html>`;
}
