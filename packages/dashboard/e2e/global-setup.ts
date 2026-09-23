import pg from "pg";

const DB_URL = process.env.DATABASE_URL || "postgresql://blindpass:localdev@127.0.0.1:5433/blindpass";

export default async function globalSetup() {
  const client = new pg.Client({ connectionString: DB_URL });
  try {
    await client.connect();
    await client.query("SELECT 1");
    console.log("[E2E globalSetup] PostgreSQL is reachable.");
  } catch {
    throw new Error(
      "[E2E Pre-flight FAILED] Cannot connect to the configured PostgreSQL test database. " +
      "Ensure the disposable service is running and DATABASE_URL is correct."
    );
  } finally {
    await client.end();
  }
}
