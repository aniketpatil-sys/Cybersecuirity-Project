/**
 * ==========================================
 * CYBERSECURITY & OSINT TOOLKIT SCRIPT
 * Author: Aniket Patil
 * Description: Multi-tool script for Hash Analysis, Threat Scanning, IP Tracking, and Cryptography.
 * ==========================================
 */

// 1. UNIVERSAL HASH CALCULATOR (Text & File)
async function handleHash() {
    const text = document.getElementById('hashText').value;
    const fileInput = document.getElementById('hashFile');
    const algo = document.getElementById('hashAlgo').value;
    const res = document.getElementById('hashResult');

    if (fileInput.files.length > 0) {
        res.innerText = "⚡ ANALYZING BINARY DATA...";
        const reader = new FileReader();
        reader.onload = (e) => {
            const wordArr = CryptoJS.lib.WordArray.create(e.target.result);
            const hash = CryptoJS[algo](wordArr);
            res.innerHTML = `[${algo.toUpperCase()}]:<br>${hash}`;
        };
        reader.readAsArrayBuffer(fileInput.files[0]);
    } else if (text) {
        const hash = CryptoJS[algo](text);
        res.innerHTML = `[${algo.toUpperCase()}]:<br>${hash}`;
    } else { 
        res.innerText = "[!] Error: Input required."; 
    }
}

// 2. FILE INTEGRITY MATCHER
async function compareFiles() {
    const f1 = document.getElementById('matchFile1').files[0];
    const f2 = document.getElementById('matchFile2').files[0];
    const res = document.getElementById('matchResult');

    if (!f1 || !f2) return alert("Select both files.");
    res.innerText = "🔍 COMPARING HASHES...";

    const getHash = (file) => new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = (e) => resolve(CryptoJS.SHA256(CryptoJS.lib.WordArray.create(e.target.result)).toString());
        reader.readAsArrayBuffer(file);
    });

    const h1 = await getHash(f1);
    const h2 = await getHash(f2);
    res.innerHTML = h1 === h2 ? `<span style="color:#00ff88">[+] ✅ MATCHED</span>` : `<span style="color:#ff003c">[-] ❌ MISMATCH</span>`;
}

// 3. VIRUSTOTAL THREAT SCANNER [FIXED CORS ISSUE]
async function scanURL() {
    const url = document.getElementById('urlInput').value;
    const res = document.getElementById('urlResult');
    const apiKey = '1367845d2c817f79269d9fc206327691da1b33829043f6668542da76647a16f5';
    
    if (!url) {
        res.innerText = "[!] Error: URL is required.";
        return;
    }
    
    res.innerText = "🛰️ CROSS-REFERENCING VT DATABASE...";

    try {
        // Converting URL to Base64 URL Safe format for VirusTotal API v3
        const id = btoa(url).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
        const vtUrl = `https://www.virustotal.com/api/v3/urls/${id}`;
        
        // Using corsproxy.io to bypass the browser's CORS restriction
        const proxyUrl = `https://corsproxy.io/?${encodeURIComponent(vtUrl)}`;

        const response = await fetch(proxyUrl, { 
            method: 'GET',
            headers: {'x-apikey': apiKey} 
        });
        
        if (!response.ok) {
            if (response.status === 404) {
                throw new Error("URL not found in VirusTotal database yet. Needs to be scanned first.");
            }
            throw new Error(`API Request Failed: ${response.status}`);
        }

        const data = await response.json();
        const s = data.data.attributes.last_analysis_stats;
        
        res.innerHTML = s.malicious > 0 
            ? `<b style="color:#ff003c">[!] THREATS DETECTED: ${s.malicious}</b>` 
            : `<b style="color:#00ff88">[+] SECURE: NO THREATS FOUND</b><br><span style="font-size:0.7rem; color:#ccc;">(Clean: ${s.harmless}, Unrated: ${s.undetected})</span>`;
            
    } catch (e) { 
        console.error("VT API Error:", e);
        res.innerHTML = `<span style="color:#ff003c">[!] Error: ${e.message}</span>`; 
    }
}

// 4. PASSWORD STRENGTH CHECKER
function checkPassword() {
    const p = document.getElementById('passInput').value;
    const res = document.getElementById('passResult');
    let s = 0;
    if (p.length >= 8) s++;
    if (/[A-Z]/.test(p)) s++;
    if (/[0-9]/.test(p)) s++;
    if (/[^a-zA-Z0-9]/.test(p)) s++;
    
    const lvls = ["DANGER 🛑", "WEAK ⚠️", "FAIR 🟠", "STRONG 🟢", "SECURE 💎"];
    res.innerHTML = `STRENGTH: <span style="color:#00f3ff">${lvls[s]}</span>`;
}

// 5. BASE64 TOOLS
function base64Action(a) {
    const i = document.getElementById('base64Input').value;
    const res = document.getElementById('base64Result');
    try { 
        res.innerText = (a === 'encode') ? btoa(i) : atob(i); 
    } catch (e) { 
        res.innerText = "[!] Format Error. Invalid Base64 string."; 
    }
}

/**
 * ==========================================
 * CYBERSECURITY TOOLKIT SCRIPT
 * Author: Aniket Patil
 * Description: Multi-tool script for Hash Analysis, Threat Scanning, and Cryptography.
 * ==========================================
 */

// 1. UNIVERSAL HASH CALCULATOR (Text & File)
async function handleHash() {
    const text = document.getElementById('hashText').value;
    const fileInput = document.getElementById('hashFile');
    const algo = document.getElementById('hashAlgo').value;
    const res = document.getElementById('hashResult');

    if (fileInput.files.length > 0) {
        res.innerText = "⚡ ANALYZING BINARY DATA...";
        const reader = new FileReader();
        reader.onload = (e) => {
            const wordArr = CryptoJS.lib.WordArray.create(e.target.result);
            const hash = CryptoJS[algo](wordArr);
            res.innerHTML = `[${algo.toUpperCase()}]:<br>${hash}`;
        };
        reader.readAsArrayBuffer(fileInput.files[0]);
    } else if (text) {
        const hash = CryptoJS[algo](text);
        res.innerHTML = `[${algo.toUpperCase()}]:<br>${hash}`;
    } else { 
        res.innerText = "[!] Error: Input required."; 
    }
}

// 2. FILE INTEGRITY MATCHER
async function compareFiles() {
    const f1 = document.getElementById('matchFile1').files[0];
    const f2 = document.getElementById('matchFile2').files[0];
    const res = document.getElementById('matchResult');

    if (!f1 || !f2) return alert("Select both files.");
    res.innerText = "🔍 COMPARING HASHES...";

    const getHash = (file) => new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = (e) => resolve(CryptoJS.SHA256(CryptoJS.lib.WordArray.create(e.target.result)).toString());
        reader.readAsArrayBuffer(file);
    });

    const h1 = await getHash(f1);
    const h2 = await getHash(f2);
    res.innerHTML = h1 === h2 ? `<span style="color:#00ff88">[+] ✅ MATCHED</span>` : `<span style="color:#ff003c">[-] ❌ MISMATCH</span>`;
}

// 3. VIRUSTOTAL THREAT SCANNER [FIXED CORS ISSUE]
async function scanURL() {
    const url = document.getElementById('urlInput').value;
    const res = document.getElementById('urlResult');
    const apiKey = '1367845d2c817f79269d9fc206327691da1b33829043f6668542da76647a16f5';
    
    if (!url) {
        res.innerText = "[!] Error: URL is required.";
        return;
    }
    
    res.innerText = "🛰️ CROSS-REFERENCING VT DATABASE...";

    try {
        const id = btoa(url).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
        const vtUrl = `https://www.virustotal.com/api/v3/urls/${id}`;
        
        const proxyUrl = `https://corsproxy.io/?${encodeURIComponent(vtUrl)}`;

        const response = await fetch(proxyUrl, { 
            method: 'GET',
            headers: {'x-apikey': apiKey} 
        });
        
        if (!response.ok) {
            if (response.status === 404) {
                throw new Error("URL not found in VirusTotal database yet. Needs to be scanned first.");
            }
            throw new Error(`API Request Failed: ${response.status}`);
        }

        const data = await response.json();
        const s = data.data.attributes.last_analysis_stats;
        
        res.innerHTML = s.malicious > 0 
            ? `<b style="color:#ff003c">[!] THREATS DETECTED: ${s.malicious}</b>` 
            : `<b style="color:#00ff88">[+] SECURE: NO THREATS FOUND</b><br><span style="font-size:0.7rem; color:#ccc;">(Clean: ${s.harmless}, Unrated: ${s.undetected})</span>`;
            
    } catch (e) { 
        console.error("VT API Error:", e);
        res.innerHTML = `<span style="color:#ff003c">[!] Error: ${e.message}</span>`; 
    }
}

// 4. PASSWORD STRENGTH CHECKER
function checkPassword() {
    const p = document.getElementById('passInput').value;
    const res = document.getElementById('passResult');
    let s = 0;
    if (p.length >= 8) s++;
    if (/[A-Z]/.test(p)) s++;
    if (/[0-9]/.test(p)) s++;
    if (/[^a-zA-Z0-9]/.test(p)) s++;
    
    const lvls = ["DANGER 🛑", "WEAK ⚠️", "FAIR 🟠", "STRONG 🟢", "SECURE 💎"];
    res.innerHTML = `STRENGTH: <span style="color:#00f3ff">${lvls[s]}</span>`;
}

// 5. BASE64 TOOLS
function base64Action(a) {
    const i = document.getElementById('base64Input').value;
    const res = document.getElementById('base64Result');
    try { 
        res.innerText = (a === 'encode') ? btoa(i) : atob(i); 
    } catch (e) { 
        res.innerText = "[!] Format Error. Invalid Base64 string."; 
    }
}

/**
 * ==========================================
 * MATRIX RAIN BACKGROUND EFFECT
 * ==========================================
 */
const canvas = document.getElementById('matrix-bg');
const ctx = canvas.getContext('2d');

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$+-*/=%""\'#&_(),.;:?!\\|{}<>[]^~日ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ';
const matrixChars = letters.split('');
const fontSize = 14;
const columns = canvas.width / fontSize;
const drops = [];

for (let x = 0; x < columns; x++) {
    drops[x] = 1;
}

function drawMatrix() {
    ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = '#0F0'; 
    ctx.font = fontSize + 'px monospace';

    for (let i = 0; i < drops.length; i++) {
        const text = matrixChars[Math.floor(Math.random() * matrixChars.length)];
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
            drops[i] = 0;
        }
        drops[i]++;
    }
}

window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
});

setInterval(drawMatrix, 40);

/**
 * ==========================================
 * TERMINAL BOOT SEQUENCE ANIMATION
 * ==========================================
 */
const bootMessages = [
    "INIT: Starting CyberShield VAPT Framework v2.0...",
    "Mounting virtual file systems............[OK]",
    "Loading WAPT scanning modules............[OK]",
    "Initializing cryptographic engines.......[OK]",
    "Establishing secure proxy connection.....[OK]",
    "Bypassing external firewalls.............[DONE]",
    "Authenticating root user.................[VERIFIED]",
    "Access Granted. Launching Interface..."
];

async function runBootSequence() {
    const bootTextDiv = document.getElementById('boot-text');
    const bootScreen = document.getElementById('boot-screen');
    const mainWrapper = document.querySelector('.main-wrapper');

    // Type out each line with a slight random delay to simulate loading
    for (let i = 0; i < bootMessages.length; i++) {
        const p = document.createElement('p');
        p.innerHTML = `root@cybershield:~# ${bootMessages[i]}`;
        bootTextDiv.appendChild(p);
        
        await new Promise(resolve => setTimeout(resolve, Math.random() * 300 + 100));
    }

    // Wait slightly before transitioning
    await new Promise(resolve => setTimeout(resolve, 600));

    // Hide the boot screen with a fade out effect
    bootScreen.classList.add('hidden-boot');

    // Show the main dashboard
    setTimeout(() => {
        bootScreen.style.display = 'none';
        mainWrapper.style.transition = 'opacity 1.5s ease-in';
        mainWrapper.style.opacity = '1';
    }, 800);
}

// Trigger the boot sequence when the page loads
window.onload = runBootSequence;