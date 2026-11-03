/* global document */

// The operator canopy dashboard (web/dashboard-server.mjs) in a real browser, on the desktop and
// phone projects. The server runs in-process against three injected Elders: one healthy, one down,
// one serving a directory that was tampered with after signing. No Tor, no network.

import { generateKeyPairSync } from "node:crypto";
import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { signCaps, signDirectory, pubkeyToOnion } from "../../packages/node/lib/directory.mjs";
import { makeDashboard, makeDashboardServer } from "../../web/dashboard-server.mjs";

function key() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    pub: publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex"),
    priv: privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("hex"),
  };
}

function gateway(i) {
  const k = key();
  const onion = pubkeyToOnion(k.pub);
  const caps = { proto: { min: 4, max: 4 }, admits: i % 2 ? ["invited", "staked"] : ["staked"], region: ["eu", "na", "eu", "as"][i % 4], ...(i === 3 ? { draining: true } : {}) };
  return { onion, pubkey: k.pub, weight: 100, health: i === 5 ? "down" : "up", operator: `0x${String(i % 3).repeat(40)}`, staked: true, caps, capsSig: signCaps(onion, caps, k.priv) };
}

const good = key();
const evil = key();
const gateways = Array.from({ length: 6 }, (_, i) => gateway(i));
const now = () => Math.floor(Date.now() / 1000);

const fetchJson = async (elder, path) => {
  if (elder.label === "down0000") throw new Error("Socks5 proxy rejected connection - HostUnreachable");
  if (path === "/health") return { ok: true, count: gateways.length, admission: "stake", commit: "c".repeat(40) };
  if (path === "/directory") {
    const dir = signDirectory({ version: 1, issued: now(), gateways, signer: elder.signer }, elder.label === "good0000" ? good.priv : evil.priv);
    if (elder.label === "tamper00") dir.gateways = dir.gateways.slice(1);
    return dir;
  }
  throw new Error("HTTP 404");
};

let server;
let base;

test.beforeAll(async () => {
  const targets = {
    network: "sepolia",
    pinnedCommit: "c".repeat(40),
    elders: [
      { label: "good0000", url: "http://good", signer: good.pub },
      { label: "down0000", url: "http://down", signer: good.pub },
      { label: "tamper00", url: "http://tamper", signer: evil.pub },
    ],
  };
  const dashboard = makeDashboard({ targets, fetchJson });
  for (let i = 0; i < 4; i++) await dashboard.tick();
  server = makeDashboardServer(dashboard, { network: "sepolia" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

test.afterAll(async () => {
  await new Promise((resolve) => (server ? server.close(resolve) : resolve()));
});

test("canopy dashboard renders every Elder, flags the bad ones, and stays accessible", async ({ page }) => {
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(e.message));

  await page.goto(`${base}/`, { waitUntil: "load" });
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(/Canopy\s*Dashboard/);
  await expect(page.locator("[data-state]")).toHaveText("Degraded: 2 of 3 Elders not verified");

  const cards = page.locator(".elder-card");
  await expect(cards).toHaveCount(3);
  await expect(page.getByRole("article", { name: "Elder good0000" }).locator(".elder-verdict")).toHaveText("verified");
  await expect(page.getByRole("article", { name: "Elder down0000" }).locator(".elder-verdict")).toHaveText("unreachable");
  await expect(page.getByRole("article", { name: "Elder down0000" })).toContainText("tor: onion unreachable");
  // The tampered directory is answered but must not verify, and none of its rows may appear.
  await expect(page.getByRole("article", { name: "Elder tamper00" }).locator(".elder-verdict")).toHaveText("unverified");
  await expect(page.locator("[data-nodes] tr")).toHaveCount(gateways.length);
  await expect(page.locator("[data-nodes]")).toContainText("draining");
  await expect(page.locator("[data-nodes]")).toContainText("down");

  // Privacy on the rendered page, not only in the API.
  const text = await page.locator("body").innerText();
  for (const g of gateways) {
    expect(text).not.toContain(g.onion);
    expect(text).not.toContain(g.operator);
  }

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
  expect(overflow).toBe(false);

  const axe = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(axe.violations).toEqual([]);
  expect(errors).toEqual([]);
});
