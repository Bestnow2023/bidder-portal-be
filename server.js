import { createServer } from "node:http";
import portalHandler from "./api/portal.js";

const port = Number(process.env.PORT || 4000);

createServer((request, response) => {
  portalHandler(request, response).catch((error) => {
    response.statusCode = 500;
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({ error: error instanceof Error ? error.message : "Unexpected error" }));
  });
}).listen(port, () => {
  console.log(`Bidder portal API listening on http://localhost:${port}`);
});
