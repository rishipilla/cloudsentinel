import assert from "node:assert/strict";
import { test } from "node:test";
import worker from "./worker.js";

test("gateway fixes the origin, replaces the client credential, and disables caching", async () => {
  const originalFetch = globalThis.fetch;
  const privateCredential = "test-only-credential-that-is-never-logged";
  let forwardedRequest;
  let fetchOptions;
  globalThis.fetch = async (request, options) => {
    forwardedRequest = request;
    fetchOptions = options;
    return new Response("upstream", {
      status: 200,
      headers: { "Cache-Control": "public, max-age=3600" },
    });
  };

  try {
    const response = await worker.fetch(
      new Request("https://gateway.invalid/api/v1/checks?next=https%3A%2F%2Fevil.invalid", {
        headers: { "X-CloudSentinel-Gateway-Secret": "attacker-controlled" },
      }),
      {
        ORIGIN_URL: "https://cloudsentinel-test.onrender.com",
        CLOUDSENTINEL_GATEWAY_SECRET: privateCredential,
      },
    );

    assert.equal(response.status, 200);
    assert.equal(await response.text(), "upstream");
    assert.equal(forwardedRequest.url, "https://cloudsentinel-test.onrender.com/api/v1/checks?next=https%3A%2F%2Fevil.invalid");
    assert.equal(forwardedRequest.headers.get("x-cloudsentinel-gateway-secret"), privateCredential);
    assert.equal(fetchOptions.cache, "no-store");
    assert.equal(response.headers.get("cache-control"), "no-store, private");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("gateway fails closed for an invalid origin without contacting it", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("fetch must not be called");
  };

  try {
    const response = await worker.fetch(
      new Request("https://gateway.invalid/"),
      {
        ORIGIN_URL: "https://example.com",
        CLOUDSENTINEL_GATEWAY_SECRET: "x".repeat(40),
      },
    );
    assert.equal(response.status, 503);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("gateway accepts a fixed Vercel HTTPS origin", async () => {
  const originalFetch = globalThis.fetch;
  let forwardedUrl;
  globalThis.fetch = async (request) => {
    forwardedUrl = request.url;
    return new Response("ok");
  };

  try {
    const response = await worker.fetch(
      new Request("https://gateway.invalid/health"),
      {
        ORIGIN_URL: "https://cloudsentinel-test.vercel.app",
        CLOUDSENTINEL_GATEWAY_SECRET: "test-only-gateway-value-for-unit-test",
      },
    );
    assert.equal(response.status, 200);
    assert.equal(forwardedUrl, "https://cloudsentinel-test.vercel.app/health");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
