import { describe, expect, it, vi } from "vitest";
import { updateRunPriority } from "../../src/services/runPriority";

const controls = {
  endpoint: "/runs/one/priority",
  csrfToken: "csrf-token",
  current: 0,
};

describe("run priority service", () => {
  it("puts the exact desired priority and validates the response", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => Response.json({ priority: 75 }));
    await expect(updateRunPriority(controls, 75, fetcher)).resolves.toBeUndefined();
    expect(fetcher).toHaveBeenCalledWith(controls.endpoint, {
      method: "PUT",
      credentials: "same-origin",
      headers: {
        "content-type": "application/json",
        "x-automata-csrf-token": controls.csrfToken,
      },
      body: JSON.stringify({ priority: 75 }),
    });
  });

  it.each([-1, 1.5, 100])("rejects invalid user priority %s before transport", async (priority) => {
    const fetcher = vi.fn<typeof fetch>();
    await expect(updateRunPriority(controls, priority, fetcher)).rejects.toThrow("invalid workflow priority");
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects HTTP and response-shape failures", async () => {
    await expect(updateRunPriority(controls, 1, async () => new Response(null, { status: 409 }))).rejects.toThrow("rejected");
    for (const body of [null, {}, { priority: "1" }, { priority: 2 }]) {
      await expect(updateRunPriority(controls, 1, async () => Response.json(body))).rejects.toThrow("invalid workflow priority response");
    }
  });
});
