//--------------------------------------------
// CONFIGURATION
//--------------------------------------------
const SERVICE_ACCOUNT_EMAIL = "fpl-838@ccccccc-9c0ca.iam.gserviceaccount.com";
const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDmsl/PRf49GbZo
sGn3MRy86o5FTZGyK8TGLWkK/7qhIHBKnlBwBBRPUJQbKqSkgyAvjnPg7S6sRYx1
QU/VO4X3Y6h2wm7QtbXtBPXq+asEUClxxc1dNtB5P1nceZn8aNkpGFH6vCeJmW0j
H3ikGPmlmrAam4BRxypksqvKzimdpUnOKODnxg4etJYHTT3MGqGj5MZ4AWYxsPyV
ushHSf45jvJM07MDol6cI7I1hRT6kvIyMG6EqHvGn+jS/BHTjEBTo8ZAhKioQZWy
ha03T0+mozDub9zlI/ufpfiof8uD7GgYuIzzF5MmW6fK82XLaURmP5/x8EnK5AgN
7XFFyjg3AgMBAAECggEAZoiRHMa3IOD0ucLu1fb2FuEJKrQ3NUFOy+YS8diHUmXg
gsmqZp7ph/cAXLKvSo8dFwXxat8AB4FB1DubB+LUwAeDMIVqS0j3+shhpHYjFF+s
i+ymQe/C6KDHh75kOlM/cYxlo1NNH1MZtqqeLBENpBUEgE7s0Wv745Wl1RWcWXvt
L87MfbmAUyB9b6g3LrkxVMrJa+BbETu8WJSDMUZpUD4xgY3PueyjcJJeBXHnmXnc
sh4IuE/Zy3jaKSbD0Hc1/qKfWF3iOfCaOfLbOeYt7tuDfDhoYH8NqcXWPf6/pSsR
oAa3s3mgqLw+TtvFykt7RAZbiD510XaTBIE17Q+UQQKBgQD151cIzvQEqd4+JD3Z
//zoUjlPeFOOCH+HdGYaS8CneIVGBEuOQ1uB56Z1flXilllpuf9d5fbeETucLWj5
WoxzP1WnYJOoN8LlGy8gmNkb2JfUrd1WL0w4QPDSrtZszPb0fVXOoQrnU/bZ4KsL
M0yggdX06HzyQEAkMo7gXK9quwKBgQDwKzJXq6VoMa8I7ViX1hjNPAxeQuFSIqoz
oiG95GPpOOvYlMEVbP2xNRsqpb9/6gMzAefYztn0pzx0SMG873IRpp2WzEdj7h1X
+kpXEi4ivtg5YXGCn9c3g/D7eV8kmpmRCjEbUmOt1w+8u3AJ0xdRbCr0hgXiwbmT
mxGOCwQmtQKBgF8yBtyPGaJwjGvsJdGuKx9ZLXyZbWdP3Ob4ZcqKRvPOUXHQmdti
MhuxLRzRIriMUeL/MWANdat0ampEnh3iMvsuqp8YYTE/HQEKrAznfy0rhWO9RzFl
MBGa+l/ldXc7ReNSXhSW/ZyeQbMJKc41NtXwTX75Pd2eh/Y7aFptJy+fAoGBAL6K
1u79bEalHGRtwdr87kJuALYMQ62heP1sBW8dszLGiT8UjbfM991O79W/GJaId69R
NLsrKXrT77+mNacLJanhUafhPEaJFNjG55H7B4VjejLUH3VuERanZFpvac+lpG6Q
8nLlw9WZCZBH+VSiGB7uPYowhpzn666y2ZOjI9D9AoGAMz+kyJwEf8BXK0Wea0M/
wUYnAJbKKC0pp1PEKyuUhYaeAc4moUcNYlxKzldIDuv8tWCh7iTaW7u0xJkVgsOJ
MLSXljhmQdiag5T2cLZJ5NxxVU8PFlMbcOvMnIJXQA60V8KeUOqKYBfSxL8K6NBn
2KQInBrKAj40dHaQ/jwX3/4=
-----END PRIVATE KEY-----`;

const SPREADSHEET_ID = "1evPhDbDY8YuIL4XQ_pvimI-17EppUkCAUfFjxJ-Bgyw";


//--------------------------------------------
// JWT + TOKEN
//--------------------------------------------
function base64url(source) {
    let encoded = btoa(String.fromCharCode(...new Uint8Array(source)));
    return encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function importPrivateKey(pemKey) {
    const pem = pemKey.replace(/-----[^-]+-----/g, "").replace(/\n/g, "");
    const binary = Uint8Array.from(atob(pem), x => x.charCodeAt(0));

    return crypto.subtle.importKey(
        "pkcs8",
        binary,
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
    const message = encHeader + "." + encClaim;

    const key = await importPrivateKey(PRIVATE_KEY);

    const signature = await crypto.subtle.sign(
        { name: "RSASSA-PKCS1-v1_5" },
        key,
        new TextEncoder().encode(message)
    );

    return message + "." + base64url(new Uint8Array(signature));
}

async function getGoogleAccessToken() {
    const jwt = await generateJWT();

    const res = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
    });

    return (await res.json()).access_token;
}


//--------------------------------------------
// UPDATE GOOGLE SHEETS RANGE
//--------------------------------------------
async function updateRange(range, values) {
    const token = await getGoogleAccessToken();

    await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}/values/${range}?valueInputOption=RAW`,
        {
            method: "PUT",
            headers: {
                "Authorization": `Bearer ${token}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ values })
        }
    );
}


//--------------------------------------------
// PROCESS ALL (ONE BUTTON)
//--------------------------------------------
document.getElementById("processAllBtn").onclick = async () => {

    const raw = document.getElementById("mainInput").value.trim();

    // Split input same as Python
    const L = raw.split("-").slice(1, -1).map(x => x.trim());

    //-------------------------
    // BUTTON 1 — K17:Q17
    //-------------------------
    await updateRange("K17:Q17", [L[0].split("")]);

    //-------------------------
    // BUTTON 2 — Y17:AF17
    //-------------------------
    await updateRange("Y17:AF17", [[L[1][0] || "", "", "", "", "", "", "", L[1][1] || ""]]);

    //-------------------------
    // BUTTON 3 — F21:I21 + N21
    //-------------------------
    await updateRange("F21:I21", [[L[2][0], L[2][1], L[2][2], L[2][3]]]);
    await updateRange("N21", [[L[2][5] || ""]]);

    //-------------------------
    // BUTTON 4 — R21:AA21
    //-------------------------
    await updateRange("R21:AA21", [[L[3].replace(/\//g, "     /     ")]]);

    //-------------------------
    // BUTTON 5 — E25:H25 + N25:Q25
    //-------------------------
    await updateRange("E25:H25", [[L[4][0], L[4][1], L[4][2], L[4][3]]]);
    await updateRange("N25:Q25", [[L[4][4], L[4][5], L[4][6], L[4][7]]]);

    //-------------------------
    // BUTTON 6 — FULL PYTHON LOGIC
    //-------------------------
    {
        let text = L[5];
        let single = text.split(/\r?\n/).join(" ");
        let words = single.split(/\s+/);

        let filtered = words.filter(w => w.length !== 6);

        let fw = filtered[0] || "";
        let firstFive = fw.substring(0, 5);
        let lastFour = fw.slice(-4);

        let rest = filtered.slice(1);

        await updateRange("B29:F29", [firstFive.split("")]);
        await updateRange("H29:L29", [lastFour.split("")]);

        // FIRST PART (≤80 chars)
        let p1 = [];
        let c1 = 0;

        for (let w of rest) {
            if (c1 + w.length + 1 <= 80) {
                p1.push(w);
                c1 += w.length + 1;
            } else break;
        }

        let p1Str = p1.join(" ");

        // SECOND PART (≤130 chars)
        let rest2 = rest.slice(p1.length);
        let p2 = [];
        let c2 = 0;

        for (let w of rest2) {
            if (c2 + w.length + 1 <= 130) {
                p2.push(w);
                c2 += w.length + 1;
            } else break;
        }

        let p2Str = p2.join(" ");

        // OVERFLOW
        let overflow = rest2.slice(p2.length).join(" ");

        if (p1Str) await updateRange("N29:AJ30", [[p1Str]]);
        if (p2Str) await updateRange("A31:AJ31", [[p2Str]]);
        if (overflow) await updateRange("A32:AJ32", [[overflow]]);
    }

    //-------------------------
    // BUTTON 7 — 4 SEGMENTS
    //-------------------------
    await updateRange("E39:H39", [L[6].substring(0, 4).split("")]);
    await updateRange("M39:P39", [L[6].substring(4, 8).split("")]);
    await updateRange("U39:X39", [L[6].substring(9, 13).split("")]);
    await updateRange("AD39:AG39", [L[6].substring(14, 18).split("")]);

    //-------------------------
    // BUTTON 8 — SPLIT 125 / 125
    //-------------------------
    {
        let text = L[7];
        let single = text.split(/\r?\n/).join(" ");
        let words = single.split(/\s+/);

        let p1 = [];
        let c1 = 0;

        for (let w of words) {
            if (c1 + w.length + 1 <= 125) {
                p1.push(w);
                c1 += w.length + 1;
            } else break;
        }

        let p1Str = p1.join(" ");

        let rest = words.slice(p1.length);
        let p2 = [];
        let c2 = 0;

        for (let w of rest) {
            if (c2 + w.length + 1 <= 125) {
                p2.push(w);
                c2 += w.length + 1;
            } else break;
        }

        let p2Str = p2.join(" ");

        await updateRange("B43:AJ43", [[p1Str]]);
        await updateRange("A44:AJ44", [[p2Str]]);
    }

    //-------------------------
    // OPEN GOOGLE SHEET
    //-------------------------
    window.open(
        "https://docs.google.com/spreadsheets/d/1evPhDbDY8YuIL4XQ_pvimI-17EppUkCAUfFjxJ-Bgyw/edit?usp=sharing",
        "_blank"
    );

    alert("✓ All lines processed and written!");
};
