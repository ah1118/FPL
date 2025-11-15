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
// JWT + TOKEN HELPERS
//--------------------------------------------
function base64url(src) {
    let encoded = btoa(String.fromCharCode.apply(null, new Uint8Array(src)));
    return encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function importPrivateKey(pemKey) {
    const pem = pemKey.replace(/-----[^-]+-----/g, "").replace(/\n/g, "");
    const bin = Uint8Array.from(atob(pem), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
        "pkcs8",
        bin,
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
    const dataToSign = encHeader + "." + encClaim;

    const privateKey = await importPrivateKey(PRIVATE_KEY);
    const signature = await crypto.subtle.sign(
        { name: "RSASSA-PKCS1-v1_5" },
        privateKey,
        new TextEncoder().encode(dataToSign)
    );

    return dataToSign + "." + base64url(new Uint8Array(signature));
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
// GOOGLE SHEET API
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

async function clearRange(range) {
    const token = await getGoogleAccessToken();
    await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}/values/${range}:clear`,
        {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${token}`,
                "Content-Type": "application/json"
            }
        }
    );
}


//--------------------------------------------
// LOADING SPINNER
//--------------------------------------------
function showSpinner() {
    document.getElementById("spinner").classList.remove("hidden");
}
function hideSpinner() {
    document.getElementById("spinner").classList.add("hidden");
}


//--------------------------------------------
// MAIN PROCESS BUTTON
//--------------------------------------------
document.getElementById("processAllBtn").onclick = async () => {

    showSpinner();

    try {

        const raw = document.getElementById("mainInput").value.trim();
        const L = raw.split("-").slice(1, -1).map(t => t.trim());

        //----------------------------------------------------
        // BUTTON 1 — K17:Q17
        //----------------------------------------------------
        await clearRange("K17:Q17");
        {
            let arr = L[0].trim().split("");
            if (arr.length === 6) arr.push("-");
            else if (arr.length !== 7) {
                alert("K17:Q17 must be 6 or 7 characters.");
                hideSpinner();
                return;
            }
            await updateRange("K17:Q17", [arr]);
        }

        //----------------------------------------------------
        // BUTTON 2 — Y17:AF17
        //----------------------------------------------------
        await clearRange("Y17:AF17");
        await updateRange("Y17:AF17", [[L[1][0] || "", "", "", "", "", "", "", L[1][1] || ""]]);

        //----------------------------------------------------
        // BUTTON 3 — F21:I21 + N21
        //----------------------------------------------------
        await clearRange("F21:I21");
        await clearRange("N21");
        await updateRange("F21:I21", [[L[2][0], L[2][1], L[2][2], L[2][3]]]);
        await updateRange("N21", [[L[2][5] || ""]]);

        //----------------------------------------------------
        // BUTTON 4 — R21:AA21
        //----------------------------------------------------
        await clearRange("R21:AA21");
        await updateRange("R21:AA21", [
            [L[3].replace(/\//g, "     /     ")]
        ]);

        //----------------------------------------------------
        // BUTTON 5 — E25:H25 + N25:Q25
        //----------------------------------------------------
        await clearRange("E25:H25");
        await clearRange("N25:Q25");
        await updateRange("E25:H25", [[L[4][0], L[4][1], L[4][2], L[4][3]]]);
        await updateRange("N25:Q25", [[L[4][4], L[4][5], L[4][6], L[4][7]]]);

        //----------------------------------------------------
        // BUTTON 6
        //----------------------------------------------------
        await clearRange("B29:F29");
        await clearRange("H29:L29");
        await clearRange("N29:AJ30");
        await clearRange("A31:AJ31");
        await clearRange("A32:AJ32");

        let t6 = L[5].replace(/\n/g, " ");
        let words6 = t6.split(/\s+/).filter(w => w.length !== 6);

        let fw = words6[0] || "";
        await updateRange("B29:F29", [fw.substring(0, 5).split("")]);
        await updateRange("H29:L29", [fw.slice(-4).split("")]);

        let rem = words6.slice(1);
        if (rem.length) {
            let part1 = [];
            let chars = 0;
            for (let w of rem) {
                if (chars + w.length + 1 <= 80) {
                    part1.push(w);
                    chars += w.length + 1;
                } else break;
            }
            let p1 = part1.join(" ");
            let rem2 = rem.slice(part1.length);

            let p2a = [];
            let c2 = 0;
            for (let w of rem2) {
                if (c2 + w.length + 1 <= 130) {
                    p2a.push(w);
                    c2 += w.length + 1;
                } else break;
            }
            let p2 = p2a.join(" ");
            let overflow = rem2.slice(p2a.length).join(" ");

            if (p1) await updateRange("N29:AJ30", [[p1]]);
            if (p2) await updateRange("A31:AJ31", [[p2]]);
            if (overflow) await updateRange("A32:AJ32", [[overflow]]);
        }

        //----------------------------------------------------
        // BUTTON 7
        //----------------------------------------------------
        await clearRange("E39:H39");
        await clearRange("M39:P39");
        await clearRange("U39:X39");
        await clearRange("AD39:AG39");

        let raw7 = L[6].replace(/[^A-Za-z0-9]/g, "");
        while (raw7.length < 16) raw7 += "-";

        await updateRange("E39:H39", [raw7.substring(0, 4).split("")]);
        await updateRange("M39:P39", [raw7.substring(4, 8).split("")]);
        await updateRange("U39:X39", [raw7.substring(8, 12).split("")]);
        await updateRange("AD39:AG39", [raw7.substring(12, 16).split("")]);

        //----------------------------------------------------
        // BUTTON 8
        //----------------------------------------------------
        await clearRange("B43:AJ43");
        await clearRange("A44:AJ44");

        let t8 = L[7].replace(/\n/g, " ");
        let w8 = t8.split(/\s+/);
        let pA = [];
        let countA = 0;

        for (let w of w8) {
            if (countA + w.length + 1 <= 125) {
                pA.push(w);
                countA += w.length + 1;
            } else break;
        }

        await updateRange("B43:AJ43", [[pA.join(" ")]]);
        await updateRange("A44:AJ44", [[w8.slice(pA.length).join(" ")]]);

        //----------------------------------------------------
        // OPEN SHEET
        //----------------------------------------------------
        window.open(
            "https://docs.google.com/spreadsheets/d/1evPhDbDY8YuIL4XQ_pvimI-17EppUkCAUfFjxJ-Bgyw/edit?usp=sharing",
            "_blank"
        );

        alert("All lines processed!");

    } catch (e) {
        alert("Error: " + e.message);
    }

    hideSpinner();
};
