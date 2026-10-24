import { parseCapture } from "./parser";
import { groupDialogs } from "./dialogs";
self.onmessage = (event: MessageEvent<ArrayBuffer>) => {
  try {
    const capture = parseCapture(event.data, (n) =>
      self.postMessage({ type: "progress", packets: n }),
    );
    self.postMessage({
      type: "result",
      dialogs: groupDialogs(capture),
      warnings: capture.warnings,
      packets: capture.packets,
    });
  } catch (error) {
    self.postMessage({
      type: "error",
      error: error instanceof Error ? error.message : String(error),
    });
  }
};
