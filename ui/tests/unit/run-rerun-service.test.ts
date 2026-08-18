import { describe, expect, it, vi } from "vitest";
import { startRunRerun } from "../../src/services/runRerun";

const controls = {
  endpoint: "/runs/one/rerun",
  csrfToken: "csrf-token",
  failedJobsAvailable: true,
};
const runId = "550e8400-e29b-41d4-a716-446655440000";

describe("run rerun service", () => {
  it("posts the exact protocol and validates the returned run", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => Response.json({ run_id: runId }));
    await expect(startRunRerun({ controls, fetcher, mode: "entire_workflow", operationId: () => "operation-one" })).resolves.toBe(runId);
    expect(fetcher).toHaveBeenCalledWith("/runs/one/rerun", expect.objectContaining({
      method: "POST",
      credentials: "same-origin",
      body: JSON.stringify({ operation_id: "operation-one", selection: { mode: "entire_workflow" } }),
    }));
  });

  it("rejects HTTP and response-shape failures", async () => {
    await expect(startRunRerun({ controls, fetcher: async () => new Response(null, { status: 409 }), mode: "entire_workflow" })).rejects.toThrow("rejected");
    await expect(startRunRerun({ controls, fetcher: async () => Response.json({ run_id: "invalid" }), mode: "failed_jobs_and_dependents" })).rejects.toThrow("invalid");
    await expect(startRunRerun({ controls, fetcher: async () => Response.json(null), mode: "entire_workflow" })).rejects.toThrow("invalid");
  });
});
