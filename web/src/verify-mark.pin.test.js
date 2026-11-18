// The vendored shared/verify-mark files (VerifyMark.jsx, VerifyMark.css) match their pin files byte for byte, and the pins are the canonical ones
// (curtismu7/AI-DEMO-Standalone shared/verify-mark, #238). Change them there, re-pin, re-vendor; never edit them here.
import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const CANON = { "VerifyMark.jsx": "5c5025e7ed2e9df8d40d313d258fa2a93368f7286d33959d81c61cd469c3cc90", "VerifyMark.css": "4774585cd47c3affc739d3d99fa6843d62f607d8d3e69b4438de756ac3d49dc5" };
const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "components");

describe("vendored verify-mark", () => {
  it("matches VerifyMark.sha256 and VerifyMark.css.sha256", () => {
    for (const [file, pinFile] of [["VerifyMark.jsx", "VerifyMark.sha256"], ["VerifyMark.css", "VerifyMark.css.sha256"]]) {
      const [hash, name] = fs.readFileSync(path.join(dir, pinFile), "utf8").trim().split(/\s+/);
      expect(name, pinFile).toBe(file);
      expect(createHash("sha256").update(fs.readFileSync(path.join(dir, file))).digest("hex"), file).toBe(hash);
    }
  });

  it("is the canonical copy", () => {
    for (const [file, hash] of Object.entries(CANON)) expect(createHash("sha256").update(fs.readFileSync(path.join(dir, file))).digest("hex"), file).toBe(hash);
  });
});
