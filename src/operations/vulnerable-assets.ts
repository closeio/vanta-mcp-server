// 1. Imports
import {
  CallToolResult,
  Tool,
  z,
  createConsolidatedSchema,
  makeConsolidatedRequest,
} from "./common/imports.js";

// 2. Input Schemas
const VulnerableAssetsInput = createConsolidatedSchema(
  {
    paramName: "vulnerableAssetId",
    description:
      "Vulnerable asset ID to retrieve, e.g. 'vulnerable-asset-123' or specific asset identifier",
    resourceName: "vulnerable asset",
  },
  {
    q: z
      .string()
      .describe("Filter vulnerable assets by search query.")
      .optional(),
    integrationId: z
      .string()
      .describe("Filter vulnerable assets by specific vulnerability scanner.")
      .optional(),
    assetType: z
      .enum([
        "CODE_REPOSITORY",
        "CONTAINER_REPOSITORY",
        "CONTAINER_REPOSITORY_IMAGE",
        "MANIFEST_FILE",
        "SERVER",
        "SERVERLESS_FUNCTION",
        "WORKSTATION",
        "OTHER",
      ])
      .describe(
        "Narrow results by asset classification. Possible values: CODE_REPOSITORY, CONTAINER_REPOSITORY, CONTAINER_REPOSITORY_IMAGE, MANIFEST_FILE, SERVER, SERVERLESS_FUNCTION, WORKSTATION, OTHER.",
      )
      .optional(),
    assetExternalAccountId: z
      .string()
      .describe("Filter vulnerable assets by external account identifier.")
      .optional(),
  },
);

// 3. Tool Definitions
export const VulnerableAssetsTool: Tool<typeof VulnerableAssetsInput> = {
  name: "vulnerable_assets",
  description:
    "Look up assets (servers, workstations, repositories, containers, etc.) in your Vanta account. Use this to resolve vulnerableAssetId values from vulnerability records into human-readable asset names and details. Provide vulnerableAssetId to get a specific asset, or omit to list all assets with optional filters. Returns asset name, type, external account, integration source, and associated vulnerability counts.",
  parameters: VulnerableAssetsInput,
};

// 4. Implementation Functions
export async function vulnerableAssets(
  args: z.infer<typeof VulnerableAssetsInput>,
): Promise<CallToolResult> {
  return makeConsolidatedRequest(
    "/v1/vulnerable-assets",
    args,
    "vulnerableAssetId",
  );
}

// Registry export for automated tool registration
export default {
  tools: [{ tool: VulnerableAssetsTool, handler: vulnerableAssets }],
};
