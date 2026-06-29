const PASSWORD = "1061993";

const entered = prompt("Enter password:");

if (entered !== PASSWORD) {
    document.body.innerHTML = "<h2>Access denied</h2>";
    throw new Error("Unauthorized");
}

//--------------------------------------------
// CONFIGURATION
//--------------------------------------------
const SERVICE_ACCOUNT_EMAIL = "fpl-web-123@fpl2024-438115.iam.gserviceaccount.com";
const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDNOVTdwpkhJVrx\nr5MIhggrk41YrOMlJaFVu8ffi0P4+k5gaynq5Nse7q4+xqswkVOfdP172P0F/uW7\nwIOYEPZEr1nQMRfiHOOXGETGL0kzj6jLP4hg50Bx3XDBHceI5n4uMd5AiZujBBYz\nok5QuxaYbjclD/mdvX5Zlw6ngoTOEIaRJ0a7SChLrhUNpj60xbvbJxSXj/16fPvL\n0nUymlu14feXGjO8NfSnoeZW8CsZypG3vB1Y9tKhl++bQVDzzUzYJWe/Jqux8cGm\n/9dTo3ojUjWXeBymNFKqiJQOfxonkQtWcwMv1sDvDDWKiK3qVJyGvF07nvellcrX\nxxDtH0E1AgMBAAECggEAG0C0y2ovKZ6rUBMPxH8AEMFccN0soN85aIgyR7ZXxXV/\n+P/iJiZUDuyFSSLa0u1JnJBNpSewmh46Zc9v6j6+ZWqf06zhTg6mDoeTgnn/D5DR\nSoRaWPv8q+JLOen5eG2bbgkDSbC8cU52oE66dbASlRV1zz8q1861O7J6qLYFatO7\nz2kEh8Cb+UtBxsQ8z/f90CrWavaoixxKtb7wLdYaQRM8+PRoLKu1cs2DdcYuICLr\nMDm9Tw/KAnPaU1ykSg8A7wTjUVfgJphWEyPM8mKLvCD8n36z/jAimPbbM1Ae3mxn\n06ucOHjMPjTpXJQNDWB0b/3s24CNhfhJ1t9OL1imgQKBgQD82DFwhvAPRiVFljwp\nN3OHKvaRkIlV1baOeaE4fPeGjH5dAVohqxW+cmoxHL3QtbenklVp4Eb7ieRhz2Xe\ns7SBYYGjfBwvn00Jm+BT/znS9QNQZGP+iyBZ7b4uel0ZbitVpahIIwh7RAig/hJy\nNnvmtKS7DDWvkwmuLewgEGcu1QKBgQDPyP8iOE+iXSA8zUbbY3iRz9m4Tdr85UII\n5YsLNeC4LrpoEs/zcYXO4whmkBHwx/7upHKCnmTq8NGQWV/ap05UoCZUn+Yc7i8J\n5Ex8eHYQDjHtvsLyZegIHmBwR+EbkHF/cmO412quTCzNt6GSlRA42hyq/0aovqGm\nQ0fGdK644QKBgGpX05NsbZM/AXYfFfaP5/s1yra2f8ymMj4CUhicFs90T8F2TB5V\nArQzEw7M89jQVQoZtert9WzeNjwdKs9b7dNs20WTcZdl/NTJxrQNaJidjGNHlfb9\nNQIdyBtsQ7Pqbjd7kSel9G9D0g1ETyXSXJJP7+jr3biWsz+a+PETdRJxAoGAB7Xt\nwddVHTFXgOodNwb58m9EJRK+jaP0T2A1SLU3IZ6aTEJmdSJBVOwX47Z08/p3+2Me\n3LoEBLPrEvA+Hl8XCQzoXzuPzoMIO9W9AOF3gCEGuUva8CPX+HUoHwKL1/oEPDaC\nfNmBm/Y3s2qdFFNzxqhRaAcRGDH6zbCxeSvbUAECgYBAWspYZelHO2HoIGFNW4yG\nmU9a6a27xHgoDLySTmY+0eRJfEASbA7pdeL6A66ZeHZsrOWcRrbU6u1v7NC9JdIf\nLbOjXIkvxWR7+XqnsqFFFdQmFz1fXnoxy2viF94GcgfN8NBUwjZ14iWJ/qS+JqKZ\n45b4A6BXeEvFUTRJN+AjkQ==\n-----END PRIVATE KEY-----`;

const SPREADSHEET_ID = "1evPhDbDY8YuIL4XQ_pvimI-17EppUkCAUfFjxJ-Bgyw";


//--------------------------------------------
// JWT + AUTH HELPERS (with token cache)
//--------------------------------------------
function base64url(source) {
    const encoded = btoa(String.fromCharCode.apply(null, new Uint8Array(source)));
    return encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function importPrivateKey(pemKey) {
    const pem = pemKey.replace(/-----[^-]+-----/g, "").replace(/\n/g, "");
    const binaryDer = Uint8Array.from(atob(pem), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
        "pkcs8",
        binaryDer,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        true,
        ["sign"]
    );
}

async function generateJWT() {
    const header = { alg: "RS256", typ: "JWT" };
    const now = Math.floor(Date.now() / 1000);

    const claim = {
        iss: SERVICE_ACCOUNT_EMAIL,
        scope: "https://www.googleapis.com/auth/spreadsheets",
        aud: "https://oauth2.googleapis.com/token",
        exp: now + 3600,
        iat: now
    };

    const encHeader = base64url(new TextEncoder().encode(JSON.stringify(header)));
    const encClaim = base64url(new TextEncoder().encode(JSON.stringify(claim)));
    const toSign = encHeader + "." + encClaim;

    const privateKey = await importPrivateKey(PRIVATE_KEY);
    const signature = await crypto.subtle.sign(
        { name: "RSASSA-PKCS1-v1_5" },
        privateKey,
        new TextEncoder().encode(toSign)
    );

    return toSign + "." + base64url(new Uint8Array(signature));
}

// token cache (≈55min)
let cachedToken = null;
let tokenExpiryMs = 0;

async function getAccessTokenCached() {
    const now = Date.now();
    if (cachedToken && now < tokenExpiryMs) {
        return cachedToken;
    }
    const jwt = await generateJWT();
    const res = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
    });

    const data = await res.json();
    cachedToken = data.access_token;
    // 55 minutes safety instead of 60
    tokenExpiryMs = now + 55 * 60 * 1000;
    return cachedToken;
}


//--------------------------------------------
// SHEET OPERATIONS (BATCH CLEAR + BATCH UPDATE)
//--------------------------------------------
async function batchClearRanges(ranges) {
    if (!ranges.length) return;
    const token = await getAccessTokenCached();

    await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}/values:batchClear`,
        {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${token}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ ranges })
        }
    );
}

async function batchUpdateValues(data) {
    if (!data.length) return;
    const token = await getAccessTokenCached();

    await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}/values:batchUpdate`,
        {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${token}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                valueInputOption: "RAW",
                data
            })
        }
    );
}


//--------------------------------------------
// PROCESS ALL BUTTON + SPINNER
//--------------------------------------------
const btn = document.getElementById("processAllBtn");
const spinner = document.getElementById("spinner");

document.getElementById("processAllBtn").onclick = async () => {
    // Show spinner + disable button
    spinner.classList.remove("hidden");
    btn.classList.add("disabled");

    try {
        const raw = document.getElementById("mainInput").value.trim();
        const L = raw.split("-").slice(1, -1).map(t => t.trim());

        const clearRanges = [
            "K17:Q17",
            "Y17:AF17",
            "F21:I21",
            "N21",
            "R21:AA21",
            "E25:H25",
            "N25:Q25",
            "B29:F29",
            "H29:L29",
            "N29:AJ30",
            "A31:AJ31",
            "A32:AJ32",
            "E39:H39",
            "M39:P39",
            "U39:X39",
            "AD39:AG39",
            "B43:AJ43",
            "A44:AJ44",
            "D55:G55"
        ];

        const updates = [];

        //----------------------------------------------------
        // BUTTON 1 — K17:Q17 (6 chars → add "-", 7 chars OK)
        //----------------------------------------------------
        {
            const txt = L[0];
            let arr = txt.split("");

            if (arr.length === 6) {
                arr.push("-");
            } else if (arr.length !== 7) {
                alert("K17:Q17 must be 6 or 7 characters.");
                throw new Error("Invalid length for K17:Q17");
            }

            updates.push({
                range: "K17:Q17",
                values: [arr]
            });
        }

        //----------------------------------------------------
        // BUTTON 2 — Y17:AF17
        //----------------------------------------------------
        {
            const l1 = L[1] || "";
            const c1 = l1[0] || "";
            const c2 = l1[1] || "";

            updates.push({
                range: "Y17:AF17",
                values: [[c1, "", "", "", "", "", "", c2]]
            });
        }

        //----------------------------------------------------
        // BUTTON 3 — F21:I21 + N21
        //----------------------------------------------------
        {
            const l2 = L[2] || "";
            updates.push({
                range: "F21:I21",
                values: [[l2[0] || "", l2[1] || "", l2[2] || "", l2[3] || ""]]
            });
            updates.push({
                range: "N21",
                values: [[l2[5] || ""]]
            });
        }

        //----------------------------------------------------
        // BUTTON 4 — R21:AA21
        //----------------------------------------------------
        {
            const l3 = L[3] || "";
            const replaced = l3.replace(/\//g, "     /     ");
            updates.push({
                range: "R21:AA21",
                values: [[replaced]]
            });
        }

        //----------------------------------------------------
        // BUTTON 5 — E25:H25 + N25:Q25
        //----------------------------------------------------
        {
            const l4 = L[4] || "";
            updates.push({
                range: "E25:H25",
                values: [[l4[0] || "", l4[1] || "", l4[2] || "", l4[3] || ""]]
            });
            updates.push({
                range: "N25:Q25",
                values: [[l4[4] || "", l4[5] || "", l4[6] || "", l4[7] || ""]]
            });
        }

        //----------------------------------------------------
        // BUTTON 6 — Long paragraph splitting
        //----------------------------------------------------
        {
            const t6 = (L[5] || "").replace(/\n/g, " ");
            const words6 = t6.split(/\s+/).filter(w => w.length !== 6);

            const fw = words6[0] || "";
            const first5 = [fw[0] || "", fw[1] || "", fw[2] || "", fw[3] || "", fw[4] || ""];
            const last4 = [
                fw.length >= 4 ? fw[fw.length - 4] : "",
                fw.length >= 3 ? fw[fw.length - 3] : "",
                fw.length >= 2 ? fw[fw.length - 2] : "",
                fw.length >= 1 ? fw[fw.length - 1] : ""
            ];

            updates.push({
                range: "B29:F29",
                values: [first5]
            });
            updates.push({
                range: "H29:L29",
                values: [last4]
            });

            const rem = words6.slice(1);
            if (rem.length) {
                // first segment max 80 chars
                let p1 = [];
                let c1len = 0;
                for (let i = 0; i < rem.length; i++) {
                    const w = rem[i];
                    const addLen = w.length + 1;
                    if (c1len + addLen <= 80) {
                        p1.push(w);
                        c1len += addLen;
                    } else break;
                }
                const p1Str = p1.join(" ");

                const rem2 = rem.slice(p1.length);

                // second segment max 130 chars
                let p2 = [];
                let c2len = 0;
                for (let i = 0; i < rem2.length; i++) {
                    const w = rem2[i];
                    const addLen = w.length + 1;
                    if (c2len + addLen <= 130) {
                        p2.push(w);
                        c2len += addLen;
                    } else break;
                }
                const p2Str = p2.join(" ");

                const overflow = rem2.slice(p2.length).join(" ");

                if (p1Str) {
                    updates.push({
                        range: "N29:AJ30",
                        values: [[p1Str]]
                    });
                }
                if (p2Str) {
                    updates.push({
                        range: "A31:AJ31",
                        values: [[p2Str]]
                    });
                }
                if (overflow) {
                    updates.push({
                        range: "A32:AJ32",
                        values: [[overflow]]
                    });
                }
            }
        }

        //----------------------------------------------------
        // BUTTON 7 — AAAA BBBB CCCC (optional DDDD)
        //----------------------------------------------------
        {
            let raw7 = (L[6] || "").replace(/[^A-Za-z0-9]/g, "");
            while (raw7.length < 16) raw7 += "-";

            const gA = [raw7[0], raw7[1], raw7[2], raw7[3]];
            const gB = [raw7[4], raw7[5], raw7[6], raw7[7]];
            const gC = [raw7[8], raw7[9], raw7[10], raw7[11]];
            const gD = [raw7[12], raw7[13], raw7[14], raw7[15]];

            updates.push({ range: "E39:H39", values: [gA] });
            updates.push({ range: "M39:P39", values: [gB] });
            updates.push({ range: "U39:X39", values: [gC] });
            updates.push({ range: "AD39:AG39", values: [gD] });
        }

        //----------------------------------------------------
        // BUTTON 8 — Long text 125 / 125
        //----------------------------------------------------
        {
            const t8 = (L[7] || "").replace(/\n/g, " ");
            const w8 = t8.split(/\s+/);

            let s1 = [];
            let len1 = 0;
            for (let i = 0; i < w8.length; i++) {
                const w = w8[i];
                const addLen = w.length + 1;
                if (len1 + addLen <= 125) {
                    s1.push(w);
                    len1 += addLen;
                } else break;
            }
            const s1Str = s1.join(" ");
            const s2Str = w8.slice(s1.length).join(" ");

            updates.push({
                range: "B43:AJ43",
                values: [[s1Str]]
            });
            updates.push({
                range: "A44:AJ44",
                values: [[s2Str]]
            });
        }

        //----------------------------------------------------
        // BUTTON 9 — Extract E/HHMM → D55:E55:F55:G55
        //----------------------------------------------------
        {
            const eMatch = raw.match(/-E\/(\d{4})/);
            let digits = ["", "", "", ""];
            if (eMatch) {
                digits = [
                    eMatch[1][0],
                    eMatch[1][1],
                    eMatch[1][2],
                    eMatch[1][3]
                ];
            }
            updates.push({
                range: "D55:G55",
                values: [digits]
            });
        }

        //----------------------------------------------------
        // SEND TO GOOGLE SHEETS (2 CALLS ONLY)
        //----------------------------------------------------
        await batchClearRanges(clearRanges);
        await batchUpdateValues(updates);

        // Open sheet (non-blocking feel)
        setTimeout(() => {
            window.open(
                "https://docs.google.com/spreadsheets/d/1evPhDbDY8YuIL4XQ_pvimI-17EppUkCAUfFjxJ-Bgyw/edit?usp=sharing",
                "_blank"
            );
        }, 50);

    } catch (err) {
        console.error(err);
        alert("Error: " + (err.message || err));

    } finally {
        spinner.classList.add("hidden");
        btn.classList.remove("disabled");
    }
};
