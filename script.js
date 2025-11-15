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
// JWT + GOOGLE TOKEN GENERATION
//--------------------------------------------

function base64url(source) {
    let encoded = btoa(String.fromCharCode.apply(null, new Uint8Array(source)));
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

    const encSignature = base64url(new Uint8Array(signature));

    return toSign + "." + encSignature;
}

async function getGoogleAccessToken() {
    const jwt = await generateJWT();
    const response = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
    });

    const data = await response.json();
    return data.access_token;
}



//--------------------------------------------
// UPDATE GOOGLE SHEETS
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
// UI INPUT PARSING
//--------------------------------------------

document.getElementById("processTextBtn").onclick = () => {
    const raw = document.getElementById("mainInput").value.trim();

    const lines = raw.split("-").slice(1, -1);

    const container = document.getElementById("linesContainer");
    container.innerHTML = "";

    window.extractedLines = [];

    lines.forEach((line, index) => {
        const lbl = document.createElement("div");
        lbl.className = "line-label";
        lbl.innerText = `Line ${index + 1}:`;

        const inp = document.createElement("textarea");
        inp.className = "small-input";
        inp.value = line.trim();

        container.appendChild(lbl);
        container.appendChild(inp);

        window.extractedLines.push(inp);
    });
};



//--------------------------------------------
// PROCESS ALL BUTTON LOGIC
//--------------------------------------------

document.getElementById("processAllBtn").onclick = async () => {

    const L = window.extractedLines.map(l => l.value.trim());

    //--------------------------------------------
    // BUTTON 1 — K17:Q17
    //--------------------------------------------
    await updateRange("K17:Q17", [L[0].split("")]);


    //--------------------------------------------
    // BUTTON 2 — Y17:AF17
    //--------------------------------------------

    const ch1 = L[1][0] || "";
    const ch2 = L[1][1] || "";
    await updateRange("Y17:AF17", [[ch1, "", "", "", "", "", "", ch2]]);


    //--------------------------------------------
    // BUTTON 3 — F21:I21 + N21
    //--------------------------------------------

    await updateRange("F21:I21", [[L[2][0], L[2][1], L[2][2], L[2][3]]]);
    await updateRange("N21", [[L[2][5] || ""]]);


    //--------------------------------------------
    // BUTTON 4 — R21:AA21
    //--------------------------------------------

    await updateRange("R21:AA21", [[L[3].replace(/\//g, "     /     ")]]);


    //--------------------------------------------
    // BUTTON 5 — E25:H25 + N25:Q25
    //--------------------------------------------

    await updateRange("E25:H25", [[L[4][0], L[4][1], L[4][2], L[4][3]]]);
    await updateRange("N25:Q25", [[L[4][4], L[4][5], L[4][6], L[4][7]]]);


    //--------------------------------------------
    // BUTTON 6 — FULL PYTHON LOGIC 1:1 EXACT
    //--------------------------------------------

    {
        let text = L[5].trim();

        let single = text.split(/\r?\n/).join(" ");

        let filteredWords = single.split(/\s+/).filter(w => w.length !== 6);

        let firstWord = filteredWords[0] || "";
        let firstFive = firstWord.substring(0, 5);
        let lastFour = firstWord.slice(-4);

        let remainingWords = filteredWords.slice(1);

        // Clear first
        await updateRange("N29:AJ30", [[""]]);
        await updateRange("A31:AJ31", [[""]]);

        // B29:F29 → first 5 chars
        await updateRange("B29:F29", [firstFive.split("")]);

        // H29:L29 → last 4 chars
        await updateRange("H29:L29", [lastFour.split("")]);

        if (remainingWords.length > 0) {

            // FIRST PART (max 80 chars)
            let firstPart = [];
            let charCount = 0;

            for (let w of remainingWords) {
                if (charCount + w.length + 1 <= 80) {
                    firstPart.push(w);
                    charCount += w.length + 1;
                } else break;
            }

            let firstPartStr = firstPart.join(" ");

            // SECOND PART (max 130 chars)
            let afterFirst = remainingWords.slice(firstPart.length);
            let secondPartStr = "";
            let charCount2 = 0;

            for (let w of afterFirst) {
                if (charCount2 + w.length + 1 <= 130) {
                    secondPartStr += w + " ";
                    charCount2 += w.length + 1;
                } else break;
            }

            secondPartStr = secondPartStr.trim();

            // OVERFLOW
            let overflowWords = afterFirst.slice(secondPartStr.split(/\s+/).length);
            let overflowStr = overflowWords.join(" ");

            // WRITE FIRST PART → N29:AJ30
            if (firstPartStr)
                await updateRange("N29:AJ30", [[firstPartStr]]);

            // WRITE SECOND PART → A31:AJ31
            if (secondPartStr)
                await updateRange("A31:AJ31", [[secondPartStr]]);

            // WRITE OVERFLOW → A32:AJ32
            if (overflowStr)
                await updateRange("A32:AJ32", [[overflowStr]]);
        }
    }


    //--------------------------------------------
    // BUTTON 7 — 4 SEGMENTS OF 4 CHARS
    //--------------------------------------------

    let partA = L[6].substring(0, 4).split("");
    let partB = L[6].substring(4, 8).split("");
    let partC = L[6].substring(9, 13).split("");
    let partD = L[6].substring(14, 18).split("");

    await updateRange("E39:H39", [partA]);
    await updateRange("M39:P39", [partB]);
    await updateRange("U39:X39", [partC]);
    await updateRange("AD39:AG39", [partD]);


    //--------------------------------------------
    // BUTTON 8 — SPLIT LONG TEXT (MAX 125 EACH)
    //--------------------------------------------

    {
        let text = L[7].trim();
        let single = text.split(/\r?\n/).join(" ");

        let words = single.split(/\s+/);

        let part1 = [];
        let p1chars = 0;

        for (let w of words) {
            if (p1chars + w.length + 1 <= 125) {
                part1.push(w);
                p1chars += w.length + 1;
            } else break;
        }

        let part1Str = part1.join(" ");

        let remaining = words.slice(part1.length);
        let part2 = [];
        let p2chars = 0;

        for (let w of remaining) {
            if (p2chars + w.length + 1 <= 125) {
                part2.push(w);
                p2chars += w.length + 1;
            } else break;
        }

        let part2Str = part2.join(" ");

        await updateRange("B43:AJ43", [[part1Str]]);
        await updateRange("A44:AJ44", [[part2Str]]);
    }


    //--------------------------------------------
    // OPEN GOOGLE SHEET
    //--------------------------------------------

    window.open(
        "https://docs.google.com/spreadsheets/d/1evPhDbDY8YuIL4XQ_pvimI-17EppUkCAUfFjxJ-Bgyw/edit?usp=sharing",
        "_blank"
    );

    alert("All lines processed!");
};
