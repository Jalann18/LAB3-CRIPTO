// ============================================================
// LAB3 CRIPTO - app.js
// JavaScript del cliente - Contiene la implementación de MD5
// EDUCATIVO: El hash se genera aquí (lado cliente) - INSEGURO
// ============================================================

// ============================================================
// IMPLEMENTACIÓN MD5 (RFC 1321)
// Esta función es la que genera el hash vulnerable
// ============================================================
async function md5(str) {
    // Usamos la API SubtleCrypto solo para SHA. Para MD5 usamos implementación pura.
    return md5Pure(str);
}

function md5Pure(string) {
    function safeAdd(x, y) {
        const lsw = (x & 0xFFFF) + (y & 0xFFFF);
        const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    }
    function bitRotateLeft(num, cnt) { return (num << cnt) | (num >>> (32 - cnt)); }
    function md5cmn(q, a, b, x, s, t) { return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b); }
    function md5ff(a,b,c,d,x,s,t){ return md5cmn((b&c)|((~b)&d),a,b,x,s,t); }
    function md5gg(a,b,c,d,x,s,t){ return md5cmn((b&d)|(c&(~d)),a,b,x,s,t); }
    function md5hh(a,b,c,d,x,s,t){ return md5cmn(b^c^d,a,b,x,s,t); }
    function md5ii(a,b,c,d,x,s,t){ return md5cmn(c^(b|(~d)),a,b,x,s,t); }

    const utf8 = unescape(encodeURIComponent(string));
    const binaryStr = Array.from(utf8).map(c => c.charCodeAt(0));
    
    const len8 = binaryStr.length;
    const len32 = len8 >> 2;
    const leftover = len8 & 3;
    
    let words = [];
    for (let i = 0; i < len32; i++) {
        words[i] = (binaryStr[i*4]) | (binaryStr[i*4+1] << 8) | (binaryStr[i*4+2] << 16) | (binaryStr[i*4+3] << 24);
    }
    
    let tmp = 0;
    for (let i = 0; i < leftover; i++) {
        tmp |= binaryStr[len32*4+i] << (i*8);
    }
    words[len32] = (words[len32] || 0) | tmp;
    words[len32] |= 0x80 << (leftover * 8);
    
    words[((len8 + 8) >> 6 << 4) + 14] = len8 * 8;
    
    let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
    
    for (let i = 0; i < words.length; i += 16) {
        const olda = a, oldb = b, oldc = c, oldd = d;
        a=md5ff(a,b,c,d,words[i+0],7,-680876936); d=md5ff(d,a,b,c,words[i+1],12,-389564586); c=md5ff(c,d,a,b,words[i+2],17,606105819); b=md5ff(b,c,d,a,words[i+3],22,-1044525330);
        a=md5ff(a,b,c,d,words[i+4],7,-176418897); d=md5ff(d,a,b,c,words[i+5],12,1200080426); c=md5ff(c,d,a,b,words[i+6],17,-1473231341); b=md5ff(b,c,d,a,words[i+7],22,-45705983);
        a=md5ff(a,b,c,d,words[i+8],7,1770035416); d=md5ff(d,a,b,c,words[i+9],12,-1958414417); c=md5ff(c,d,a,b,words[i+10],17,-42063); b=md5ff(b,c,d,a,words[i+11],22,-1990404162);
        a=md5ff(a,b,c,d,words[i+12],7,1804603682); d=md5ff(d,a,b,c,words[i+13],12,-40341101); c=md5ff(c,d,a,b,words[i+14],17,-1502002290); b=md5ff(b,c,d,a,words[i+15],22,1236535329);
        a=md5gg(a,b,c,d,words[i+1],5,-165796510); d=md5gg(d,a,b,c,words[i+6],9,-1069501632); c=md5gg(c,d,a,b,words[i+11],14,643717713); b=md5gg(b,c,d,a,words[i+0],20,-373897302);
        a=md5gg(a,b,c,d,words[i+5],5,-701558691); d=md5gg(d,a,b,c,words[i+10],9,38016083); c=md5gg(c,d,a,b,words[i+15],14,-660478335); b=md5gg(b,c,d,a,words[i+4],20,-405537848);
        a=md5gg(a,b,c,d,words[i+9],5,568446438); d=md5gg(d,a,b,c,words[i+14],9,-1019803690); c=md5gg(c,d,a,b,words[i+3],14,-187363961); b=md5gg(b,c,d,a,words[i+8],20,1163531501);
        a=md5gg(a,b,c,d,words[i+13],5,-1444681467); d=md5gg(d,a,b,c,words[i+2],9,-51403784); c=md5gg(c,d,a,b,words[i+7],14,1735328473); b=md5gg(b,c,d,a,words[i+12],20,-1926607734);
        a=md5hh(a,b,c,d,words[i+5],4,-378558); d=md5hh(d,a,b,c,words[i+8],11,-2022574463); c=md5hh(c,d,a,b,words[i+11],16,1839030562); b=md5hh(b,c,d,a,words[i+14],23,-35309556);
        a=md5hh(a,b,c,d,words[i+1],4,-1530992060); d=md5hh(d,a,b,c,words[i+4],11,1272893353); c=md5hh(c,d,a,b,words[i+7],16,-155497632); b=md5hh(b,c,d,a,words[i+10],23,-1094730640);
        a=md5hh(a,b,c,d,words[i+13],4,681279174); d=md5hh(d,a,b,c,words[i+0],11,-358537222); c=md5hh(c,d,a,b,words[i+3],16,-722521979); b=md5hh(b,c,d,a,words[i+6],23,76029189);
        a=md5hh(a,b,c,d,words[i+9],4,-640364487); d=md5hh(d,a,b,c,words[i+12],11,-421815835); c=md5hh(c,d,a,b,words[i+15],16,530742520); b=md5hh(b,c,d,a,words[i+2],23,-995338651);
        a=md5ii(a,b,c,d,words[i+0],6,-198630844); d=md5ii(d,a,b,c,words[i+7],10,1126891415); c=md5ii(c,d,a,b,words[i+14],15,-1416354905); b=md5ii(b,c,d,a,words[i+5],21,-57434055);
        a=md5ii(a,b,c,d,words[i+12],6,1700485571); d=md5ii(d,a,b,c,words[i+3],10,-1894986606); c=md5ii(c,d,a,b,words[i+10],15,-1051523); b=md5ii(b,c,d,a,words[i+1],21,-2054922799);
        a=md5ii(a,b,c,d,words[i+8],6,1873313359); d=md5ii(d,a,b,c,words[i+15],10,-30611744); c=md5ii(c,d,a,b,words[i+6],15,-1560198380); b=md5ii(b,c,d,a,words[i+13],21,1309151649);
        a=md5ii(a,b,c,d,words[i+4],6,-145523070); d=md5ii(d,a,b,c,words[i+11],10,-1120210379); c=md5ii(c,d,a,b,words[i+2],15,718787259); b=md5ii(b,c,d,a,words[i+9],21,-343485551);
        a=safeAdd(a,olda); b=safeAdd(b,oldb); c=safeAdd(c,oldc); d=safeAdd(d,oldd);
    }
    
    const result = [a, b, c, d];
    return result.map(n => {
        const hex = [];
        for (let i = 0; i < 4; i++) {
            hex.push(('0' + ((n >>> (i*8)) & 0xff).toString(16)).slice(-2));
        }
        return hex.join('');
    }).join('');
}

// SHA1 usando Web Crypto API
async function sha1(str) {
    const buf = new TextEncoder().encode(str);
    const hashBuf = await crypto.subtle.digest('SHA-1', buf);
    return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// SHA256 usando Web Crypto API
async function sha256(str) {
    const buf = new TextEncoder().encode(str);
    const hashBuf = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// ============================================================
// FUNCIONES DE UI
// ============================================================

// Calcular hashes en la calculadora de la página principal
async function calculateHashes() {
    const input = document.getElementById('calc-input');
    if (!input) return;
    const text = input.value;
    
    const [m, s1, s256] = await Promise.all([md5(text), sha1(text), sha256(text)]);
    
    const el_md5 = document.getElementById('result-md5');
    const el_sha1 = document.getElementById('result-sha1');
    const el_sha256 = document.getElementById('result-sha256');
    
    if (el_md5) { el_md5.textContent = m; el_md5.classList.add('hash-flash'); setTimeout(() => el_md5.classList.remove('hash-flash'), 500); }
    if (el_sha1) el_sha1.textContent = s1;
    if (el_sha256) el_sha256.textContent = s256;
}

// Copiar hash al portapapeles
function copyHash(elementId) {
    const text = document.getElementById(elementId)?.textContent;
    if (text && text !== '-') copyText(text);
}

function copyText(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('¡Copiado al portapapeles!');
    }).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast('¡Copiado!');
    });
}

// Toast notification
function showToast(msg) {
    let toast = document.getElementById('toast-msg');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'toast-msg';
        toast.className = 'toast';
        document.body.appendChild(toast);
    }
    toast.textContent = msg;
    toast.classList.add('toast-show');
    setTimeout(() => toast.classList.remove('toast-show'), 2500);
}

// Alert dentro de la página
function showAlert(msg, type) {
    let el = document.getElementById('page-alert');
    if (!el) {
        el = document.createElement('div');
        el.id = 'page-alert';
        el.className = 'page-alert';
        const form = document.querySelector('.auth-form-panel') || document.querySelector('main');
        if (form) form.prepend(el);
    }
    el.className = `page-alert alert-${type}`;
    el.textContent = msg;
    el.style.display = 'block';
    setTimeout(() => { el.style.display = 'none'; }, 5000);
}

// Mostrar/ocultar contraseña
function togglePassword(inputId, btn) {
    const input = document.getElementById(inputId);
    if (!input) return;
    if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = '🙈';
    } else {
        input.type = 'password';
        btn.textContent = '👁';
    }
}

// Estado de carga de botones
function setBtnLoading(btnId, loading) {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    const text = btn.querySelector('.btn-text');
    const loadEl = btn.querySelector('.btn-loading');
    if (loading) {
        btn.disabled = true;
        text?.classList.add('hidden');
        loadEl?.classList.remove('hidden');
    } else {
        btn.disabled = false;
        text?.classList.remove('hidden');
        loadEl?.classList.add('hidden');
    }
}

// Calcular hashes con Enter en la calculadora
document.addEventListener('DOMContentLoaded', function() {
    const calcInput = document.getElementById('calc-input');
    if (calcInput) {
        calcInput.addEventListener('keyup', function(e) {
            if (e.key === 'Enter') calculateHashes();
        });
        calculateHashes();
    }
    
    console.log('%c[LAB3 CRIPTO] Herramientas de Laboratorio', 'color: #00ff88; font-size: 16px; font-weight: bold;');
    console.log('%cFunciones disponibles en consola:', 'color: #aaa;');
    console.log('%cmd5("texto")     → Promise<string>', 'color: #00d4ff; font-family: monospace;');
    console.log('%csha1("texto")    → Promise<string>', 'color: #00d4ff; font-family: monospace;');
    console.log('%csha256("texto")  → Promise<string>', 'color: #00d4ff; font-family: monospace;');
    console.log('%cEjemplo: md5("password123").then(h => console.log(h))', 'color: #ffd700; font-family: monospace;');
});
