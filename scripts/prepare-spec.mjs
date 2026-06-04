// Fetches yauth-go's published OpenAPI spec and writes the frontend client's
// spec to ./openapi.json.
//
// SCIM (`/api/scim/v2/*`) is stripped: it is server-to-server provisioning
// (Okta/Entra → yauth) that the Vue frontend never calls, and its
// `ScimGroupMemberBody` schema has a property literally named `$ref` (RFC 7643
// member reference) which orval's reference resolver mishandles. Stripping it
// yields a leaner, frontend-relevant client and a generator that runs clean.
import { writeFileSync } from "node:fs";

const SPEC_URL =
	"https://raw.githubusercontent.com/yackey-labs/yauth-go/main/openapi.json";

const res = await fetch(SPEC_URL);
if (!res.ok) {
	console.error(`prepare-spec: fetch failed: ${res.status} ${res.statusText}`);
	process.exit(1);
}
const spec = await res.json();

for (const path of Object.keys(spec.paths ?? {})) {
	if (path.startsWith("/api/scim/")) delete spec.paths[path];
}
for (const name of Object.keys(spec.components?.schemas ?? {})) {
	if (name.startsWith("Scim")) delete spec.components.schemas[name];
}

writeFileSync("openapi.json", `${JSON.stringify(spec, null, 2)}\n`);
console.log(
	`prepare-spec: wrote openapi.json (${Object.keys(spec.paths).length} paths, SCIM stripped)`,
);
