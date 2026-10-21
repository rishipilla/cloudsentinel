const ORIGIN_HEADER = "x-cloudsentinel-gateway-secret";

function configuredOrigin(value) {
  let origin;
  try {
    origin = new URL(value);
  } catch {
    return null;
  }

  if (
    origin.protocol !== "https:" ||
    !(
      origin.hostname.endsWith(".onrender.com") ||
      origin.hostname.endsWith(".vercel.app")
    ) ||
    origin.username ||
    origin.password ||
    origin.port ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash
  ) {
    return null;
  }
  return origin;
}

export default {
  async fetch(request, env) {
    const origin = configuredOrigin(env.ORIGIN_URL || "");
    const gatewaySecret = env.CLOUDSENTINEL_GATEWAY_SECRET || "";
    if (!origin || gatewaySecret.length < 32) {
      return new Response("Gateway configuration unavailable.", { status: 503 });
    }

    const incoming = new URL(request.url);
    origin.pathname = incoming.pathname;
    origin.search = incoming.search;

    try {
      const originRequest = new Request(origin, request);
      const headers = new Headers(originRequest.headers);
      // Never trust a browser-supplied copy; the gateway always replaces it.
      headers.delete(ORIGIN_HEADER);
      headers.delete("host");
      headers.set(ORIGIN_HEADER, gatewaySecret);
      const upstreamResponse = await fetch(
        new Request(originRequest, { headers, redirect: "manual" }),
        { cache: "no-store" },
      );
      const responseHeaders = new Headers(upstreamResponse.headers);
      responseHeaders.set("Cache-Control", "no-store, private");
      return new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        statusText: upstreamResponse.statusText,
        headers: responseHeaders,
      });
    } catch {
      // Do not log request data, the origin credential, or upstream details.
      return new Response("Upstream service unavailable.", { status: 502 });
    }
  },
};
