// 1. Imports
import {
  CallToolResult,
  Tool,
  z,
  createConsolidatedSchema,
  makeConsolidatedRequest,
} from "./common/imports.js";

// 2. Input Schemas
const VulnerabilitiesInput = createConsolidatedSchema(
  {
    paramName: "vulnerabilityId",
    description:
      "Vulnerability ID to retrieve, e.g. 'vulnerability-123' or specific vulnerability identifier. If provided, returns the specific vulnerability, and no other parameters may be provided. If omitted, lists all vulnerabilities with optional filtering and pagination.",
    resourceName: "vulnerability",
  },
  {
    q: z
      .string()
      .describe(
        "Filter vulnerabilities by a search query, such as text appearing in vulnerability details.",
      )
      .optional(),
    externalVulnerabilityId: z
      .string()
      .describe(
        "Filter vulnerabilities by external vulnerability ID (e.g. CVE-2024-1234). Returns vulnerabilities that match the provided external vulnerability ID.",
      )
      .optional(),
    severity: z
      .enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
      .describe(
        "Filter vulnerabilities by severity. Possible values: LOW, MEDIUM, HIGH, CRITICAL.",
      )
      .optional(),
    integrationId: z
      .string()
      .describe(
        "Filter vulnerabilities by integration ID. Returns vulnerabilities associated with the specified integration.",
      )
      .optional(),
    isDeactivated: z
      .boolean()
      .describe("Filter vulnerabilities by deactivation status.")
      .optional(),
    isFixAvailable: z
      .boolean()
      .describe("Filter vulnerabilities to only those which have an available fix.")
      .optional(),
    packageIdentifier: z
      .string()
      .describe(
        "Filter vulnerabilities originating from a specific software package.",
      )
      .optional(),
    slaDeadlineAfterDate: z
      .string()
      .describe(
        "Filter vulnerabilities with a 'remediate by' deadline after a specified timestamp (ISO 8601, e.g. 2024-01-01T00:00:00Z).",
      )
      .optional(),
    slaDeadlineBeforeDate: z
      .string()
      .describe(
        "Filter vulnerabilities that need to be remediated before a specific timestamp (ISO 8601, e.g. 2024-06-01T00:00:00Z).",
      )
      .optional(),
    includeVulnerabilitiesWithoutSlas: z
      .boolean()
      .describe("Include vulnerabilities that lack a specified SLA due date.")
      .optional(),
    vulnerableAssetId: z
      .string()
      .describe(
        "Filter vulnerabilities by the asset they affect, identified by a vulnerable asset ID.",
      )
      .optional(),
  },
);

// 3. Tool Definitions
export const VulnerabilitiesTool: Tool<typeof VulnerabilitiesInput> = {
  name: "vulnerabilities",
  description:
    "Access vulnerabilities in your Vanta account. Provide vulnerabilityId to get a specific vulnerability, or omit to list all vulnerabilities. Returns vulnerability details, severity levels, and status for security monitoring.",
  parameters: VulnerabilitiesInput,
};

// 4. Implementation Functions
export async function vulnerabilities(
  args: z.infer<typeof VulnerabilitiesInput>,
): Promise<CallToolResult> {
  return makeConsolidatedRequest(
    "/v1/vulnerabilities",
    args,
    "vulnerabilityId",
  );
}

// Registry export for automated tool registration
export default {
  tools: [{ tool: VulnerabilitiesTool, handler: vulnerabilities }],
};
