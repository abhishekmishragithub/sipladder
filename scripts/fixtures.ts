import { mkdirSync, writeFileSync } from "node:fs";
import { cases } from "../tests/fixtures";
import { parseCapture } from "../src/parser";
import { groupDialogs, sanitizedLadder } from "../src/dialogs";
mkdirSync("tests/corpus", { recursive: true });
mkdirSync("public/samples", { recursive: true });
for (const [name, make] of Object.entries(cases)) {
  const buffer = make();
  writeFileSync(
    `tests/corpus/${name}.${name === "multi-interface" ? "pcapng" : "pcap"}`,
    new Uint8Array(buffer),
  );
  if (process.argv.includes("--update-golden"))
    writeFileSync(
      `tests/golden/${name}.txt`,
      groupDialogs(parseCapture(buffer)).map(sanitizedLadder).join("\n\n") +
        "\n",
    );
}
writeFileSync("public/samples/answered.pcap", new Uint8Array(cases.answered()));
