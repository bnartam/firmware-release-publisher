import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import os from "node:os";
import duckdb from "duckdb";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const APP_ROOT = path.resolve(__dirname, "..");

const MANIFEST_PATH = path.join(
    APP_ROOT,
    "fixtures",
    "build_manifest.csv"
);

const DB_PATH = path.join(
    APP_ROOT,
    "releases.duckdb"
);

const CURRENT_KEY_PATH = path.join(
    APP_ROOT,
    "keys",
    "current",
    "current.key.pem"
);

const CURRENT_CERT_PATH = path.join(
    APP_ROOT,
    "keys",
    "current",
    "current.cert.pem"
);


const GATEWAY_URL =
    process.env.GATEWAY_URL ?? "http://127.0.0.1:7070";

const db = new duckdb.Database(DB_PATH);
const connection = db.connect();


function run(connection, sql, params = []) {
    return new Promise((resolve, reject) => {
        const callback = function (error) {
            if (error) {
                reject(error);
                return;
            }

            resolve(this);
        };

        if (params.length === 0) {
            connection.run(sql, callback);
        } else {
            connection.run(sql, ...params, callback);
        }
    });
}


function all(connection, sql, params = []) {
    return new Promise((resolve, reject) => {
        const callback = (error, rows) => {
            if (error) {
                reject(error);
                return;
            }

            resolve(rows);
        };

        if (params.length === 0) {
            connection.all(sql, callback);
        } else {
            connection.all(sql, ...params, callback);
        }
    });
}


async function initializeDatabase() {
    const manifestPathForDuckDB = MANIFEST_PATH.replace(/\\/g, "/");

    await run(
        connection,
        `
        CREATE TABLE IF NOT EXISTS manifest AS
        SELECT *
        FROM read_csv_auto('${manifestPathForDuckDB}')
        `
    );

    await run(
        connection,
        `
        CREATE TABLE IF NOT EXISTS publications (
            bundle_id VARCHAR PRIMARY KEY,
            request_token VARCHAR UNIQUE,
            publication_id VARCHAR,
            status VARCHAR
        )
        `
    );
}


async function getPublishableBundles() {
    return all(
        connection,
        `
        WITH unique_rows AS (
            SELECT DISTINCT *
            FROM manifest
        ),

        withdrawn_builds AS (
            SELECT DISTINCT supersedes_id
            FROM unique_rows
            WHERE record_type = 'WITHDRAWAL'
              AND supersedes_id IS NOT NULL
        ),

        surviving_builds AS (
            SELECT b.*
            FROM unique_rows b
            WHERE b.record_type = 'BUILD'
              AND NOT EXISTS (
                  SELECT 1
                  FROM withdrawn_builds w
                  WHERE w.supersedes_id = b.entry_id
              )
        )

        SELECT
            bundle_id,
            COUNT(*) AS artifact_count,
            SUM(size_bytes) AS total_bytes
        FROM surviving_builds
        GROUP BY bundle_id
        ORDER BY bundle_id
        `
    );
}


function buildDescriptor(row) {
    const descriptorObject = {
        artifact_count: Number(row.artifact_count),
        bundle_id: row.bundle_id,
        total_bytes: Number(row.total_bytes)
    };

    return JSON.stringify(
        Object.fromEntries(
            Object.entries(descriptorObject).sort(
                ([a], [b]) => a.localeCompare(b)
            )
        )
    );
}


function signDescriptor(descriptor) {
    const tempDir = fs.mkdtempSync(
        path.join(os.tmpdir(), "publisher-")
    );

    const descriptorPath = path.join(
        tempDir,
        "descriptor.bin"
    );

    const signaturePath = path.join(
        tempDir,
        "signature.pem"
    );

    try {
        fs.writeFileSync(
            descriptorPath,
            descriptor,
            "utf8"
        );

        execFileSync("openssl", [
            "cms",
            "-sign",
            "-in",
            descriptorPath,
            "-signer",
            CURRENT_CERT_PATH,
            "-inkey",
            CURRENT_KEY_PATH,
            "-outform",
            "PEM",
            "-out",
            signaturePath,
            "-binary"
        ]);

        return fs.readFileSync(
            signaturePath,
            "utf8"
        );
    } catch (error) {
        throw new Error(
            `OpenSSL signing failed: ${error.message}`
        );
    } finally {
        fs.rmSync(tempDir, {
            recursive: true,
            force: true
        });
    }
}


async function getCurrentSigningKey() {
    const response = await fetch(
        `${GATEWAY_URL}/v1/signing-key/current`
    );

    const result = await response.json();

    if (!response.ok) {
        throw new Error(
            `Failed to get current signing key: ${JSON.stringify(result)}`
        );
    }

    if (result.status !== "current") {
        throw new Error(
            `Gateway did not return a current signing key: ${JSON.stringify(result)}`
        );
    }

    return result;
}


async function publishBundle(
    descriptor,
    signature,
    requestToken
) {
    const response = await fetch(
        `${GATEWAY_URL}/v1/publications`,
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                descriptor,
                signature,
                request_token: requestToken
            })
        }
    );

    const result = await response.json();

    if (!response.ok) {
        throw new Error(
            `Publication failed: ${JSON.stringify(result)}`
        );
    }

    if (result.status !== "PUBLISHED") {
        throw new Error(
            `Gateway did not publish bundle: ${JSON.stringify(result)}`
        );
    }

    return result;
}


async function getStoredPublication(bundleId) {
    const rows = await all(
        connection,
        `
        SELECT
            bundle_id,
            request_token,
            publication_id,
            status
        FROM publications
        WHERE bundle_id = ?
        `,
        [bundleId]
    );

    return rows.length > 0 ? rows[0] : null;
}


async function savePublication(
    bundleId,
    requestToken,
    publicationId,
    status
) {
    await run(
        connection,
        `
        INSERT INTO publications (
            bundle_id,
            request_token,
            publication_id,
            status
        )
        VALUES (?, ?, ?, ?)
        `,
        [
            bundleId,
            requestToken,
            publicationId,
            status
        ]
    );
}


async function processBundle(bundle) {
    const bundleId = bundle.bundle_id;
    const requestToken = `token-${bundleId}`;

    const stored = await getStoredPublication(bundleId);

    if (stored) {
        return {
            bundleId,
            requestToken: stored.request_token,
            publicationId: stored.publication_id,
            status: stored.status
        };
    }

    const descriptor = buildDescriptor(bundle);

    const signature = signDescriptor(descriptor);

    const receipt = await publishBundle(
        descriptor,
        signature,
        requestToken
    );

    await savePublication(
        bundleId,
        receipt.request_token,
        receipt.publication_id,
        receipt.status
    );

    return {
        bundleId,
        requestToken: receipt.request_token,
        publicationId: receipt.publication_id,
        status: receipt.status
    };
}


async function main() {
    await initializeDatabase();

    const signingKey = await getCurrentSigningKey();

    const bundles = await getPublishableBundles();

    for (const bundle of bundles) {
        const result = await processBundle(bundle);

        console.log(
            `BUNDLE ${result.bundleId} SIGNED KEY=${signingKey.key_id}`
        );

        console.log(
            `BUNDLE ${result.bundleId} PUBLISHED ` +
            `RECEIPT=${result.publicationId} ` +
            `TOKEN=${result.requestToken} ` +
            `STATUS=${result.status}`
        );
    }
}


try {
    await main();
} catch (error) {
    console.error(error.message);
    process.exitCode = 1;
}