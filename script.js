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
// JWT AUTH (FAST)
//--------------------------------------------
function base64url(buffer) {
    return btoa(String.fromCharCode(...buffer))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function importPrivateKey(pem) {
    const stripped = pem.replace(/-----[^-]+-----/g, "").replace(/\n/g, "");
    const der = Uint8Array.from(atob(stripped), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
        "pkcs8", der,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        true, ["sign"]
    );
}

async function getAccessToken() {
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
    const toSign = `${encHeader}.${encClaim}`;

    const key = await importPrivateKey(PRIVATE_KEY);
    const signature = await crypto.subtle.sign(
        { name: "RSASSA-PKCS1-v1_5" },
        key,
        new TextEncoder().encode(toSign)
    );

    const jwt = `${toSign}.${base64url(new Uint8Array(signature))}`;

    const res = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
    });

    return (await res.json()).access_token;
}


//--------------------------------------------
// PROCESS BUTTON
//--------------------------------------------
const btn = document.getElementById("processAllBtn");
const spinner = document.getElementById("spinner");

document.getElementById("processAllBtn").onclick = async () => {

    spinner.classList.remove("hidden");
    btn.classList.add("disabled");

    try {
        const raw = document.getElementById("mainInput").value.trim();

        // SPLIT TEXT
        const L = raw.split("-").slice(1, -1).map(v => v.trim());

        //
        // -------- PARSE ALL VALUES ONCE --------
        //

        // BUTTON 1
        let txt1 = L[0].trim().split("");
        if (txt1.length === 6) txt1.push("-");
        if (txt1.length !== 7) throw new Error("Invalid K17:Q17 length");

        // BUTTON 2
        const b2 = [L[1][0] || "", "", "", "", "", "", "", L[1][1] || ""];

        // BUTTON 3
        const b3_1 = [L[2][0], L[2][1], L[2][2], L[2][3]];
        const b3_2 = [L[2][5] || ""];

        // BUTTON 4
        const b4 = [L[3].replace(/\//g, "     /     ")];

        // BUTTON 5
        const b5_1 = [L[4][0], L[4][1], L[4][2], L[4][3]];
        const b5_2 = [L[4][4], L[4][5], L[4][6], L[4][7]];

        // BUTTON 6
        let t6 = L[5].replace(/\n/g, " ");
        let words6 = t6.split(/\s+/).filter(w => w.length !== 6);
        let fw = words6[0] || "";
        const b6_first5 = fw.substring(0, 5).split("");
        const b6_last4 = fw.slice(-4).split("");

        let rem = words6.slice(1);
        let p1 = [], len1 = 0;
        rem.forEach(w => { if (len1 + w.length + 1 <= 80) { p1.push(w); len1 += w.length + 1; } });
        let p1Str = p1.join(" ");
        let rem2 = rem.slice(p1.length);

        let p2 = [], len2 = 0;
        rem2.forEach(w => { if (len2 + w.length + 1 <= 130) { p2.push(w); len2 += w.length + 1; } });
        let p2Str = p2.join(" ");
        let overflow = rem2.slice(p2.length).join(" ");

        // BUTTON 7
        let raw7 = L[6].replace(/[^A-Za-z0-9]/g, "");
        while (raw7.length < 16) raw7 += "-";
        const b7a = raw7.substring(0, 4).split("");
        const b7b = raw7.substring(4, 8).split("");
        const b7c = raw7.substring(8, 12).split("");
        const b7d = raw7.substring(12, 16).split("");

        // BUTTON 8
        let t8 = L[7].replace(/\n/g, " ");
        let w8 = t8.split(/\s+/);
        let s1 = [], len8 = 0;
        w8.forEach(w => { if (len8 + w.length + 1 <= 125) { s1.push(w); len8 += w.length + 1; } });
        const s1Str = s1.join(" ");
        const s2Str = w8.slice(s1.length).join(" ");

        // BUTTON 9 (E/XXXX)
        const enduranceMatch = raw.match(/-E\/(\d{4})/);
        const endurance = enduranceMatch ? enduranceMatch[1].split("") : ["","","",""];


        //
        // --------- BUILD ONE BATCH UPDATE ---------
        //

        const token = await getAccessToken();

        const batch = {
            valueInputOption: "RAW",
            data: [
                // BUTTON 1
                { range: "K17:Q17", values: [txt1] },

                // BUTTON 2
                { range: "Y17:AF17", values: [b2] },

                // BUTTON 3
                { range: "F21:I21", values: [b3_1] },
                { range: "N21", values: [b3_2] },

                // BUTTON 4
                { range: "R21:AA21", values: [b4] },

                // BUTTON 5
                { range: "E25:H25", values: [b5_1] },
                { range: "N25:Q25", values: [b5_2] },

                // BUTTON 6
                { range: "B29:F29", values: [b6_first5] },
                { range: "H29:L29", values: [b6_last4] },
                { range: "N29:AJ30", values: [ [p1Str] ] },
                { range: "A31:AJ31", values: [ [p2Str] ] },
                { range: "A32:AJ32", values: [ [overflow] ] },

                // BUTTON 7
                { range: "E39:H39", values: [b7a] },
                { range: "M39:P39", values: [b7b] },
                { range: "U39:X39", values: [b7c] },
                { range: "AD39:AG39", values: [b7d] },

                // BUTTON 8
                { range: "B43:AJ43", values: [ [s1Str] ] },
                { range: "A44:AJ44", values: [ [s2Str] ] },

                // BUTTON 9 (E/HHMM)
                { range: "D55:G55", values: [endurance] },
            ]
        };

        // SEND ONE SINGLE REQUEST
        await fetch(
            `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}/values:batchUpdate`,
            {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(batch)
            }
        );

        window.open(
            `https://docs.google.com/spreadsheets/d/${SPREADSHEET_ID}/edit?usp=sharing`,
            "_blank"
        );

    } catch (err) {
        alert("ERROR: " + err.message);
        console.error(err);
    } finally {
        spinner.classList.add("hidden");
        btn.classList.remove("disabled");
    }
};
