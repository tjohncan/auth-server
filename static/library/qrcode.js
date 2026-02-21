/**
 * qrcode.js — Zero-dependency QR Code SVG generator
 *
 * ISO/IEC 18004 compliant. Versions 1-15, all EC levels.
 * Default: Level H (30% error recovery).
 *
 * Usage:
 *   const svg = QRCode.toSVG('otpauth://totp/...', { size: 256 });
 *   QRCode.render('otpauth://totp/...', element, { size: 256 });
 */
(function(exports) {
'use strict';

/* ===========================================================================
 * Galois Field GF(2^8) — primitive polynomial x^8+x^4+x^3+x^2+1 (0x11D)
 * =========================================================================== */

var GF_EXP = new Uint8Array(512);
var GF_LOG = new Uint8Array(256);

(function() {
    var v = 1;
    for (var i = 0; i < 255; i++) {
        GF_EXP[i] = v;
        GF_EXP[i + 255] = v;
        GF_LOG[v] = i;
        v = (v << 1) ^ (v >= 128 ? 0x11D : 0);
    }
})();

function gfMul(a, b) {
    return (a && b) ? GF_EXP[GF_LOG[a] + GF_LOG[b]] : 0;
}

/* ===========================================================================
 * Reed-Solomon Error Correction
 * =========================================================================== */

var _genCache = {};

function rsGenPoly(n) {
    if (_genCache[n]) return _genCache[n];
    var g = [1];
    for (var i = 0; i < n; i++) {
        var ng = new Array(g.length + 1);
        for (var k = 0; k < ng.length; k++) ng[k] = 0;
        for (var j = 0; j < g.length; j++) {
            ng[j] ^= g[j];
            ng[j + 1] ^= gfMul(g[j], GF_EXP[i]);
        }
        g = ng;
    }
    return (_genCache[n] = g);
}

function rsEncode(data, ecCount) {
    var gen = rsGenPoly(ecCount);
    var rem = new Uint8Array(ecCount);
    for (var i = 0; i < data.length; i++) {
        var fb = data[i] ^ rem[0];
        for (var j = 0; j < ecCount - 1; j++) rem[j] = rem[j + 1];
        rem[ecCount - 1] = 0;
        if (fb) {
            for (var j = 0; j < ecCount; j++) rem[j] ^= gfMul(gen[j + 1], fb);
        }
    }
    return rem;
}

/* ===========================================================================
 * QR Code Tables (ISO 18004)
 * =========================================================================== */

/* EC level indices */
var EC_L = 0, EC_M = 1, EC_Q = 2, EC_H = 3;

/* EC_BLOCKS[version][level] = [ecPerBlock, g1Count, g1DataPer, g2Count, g2DataPer] */
var EC_BLOCKS = [
    null,
    [[7,1,19,0,0],[10,1,16,0,0],[13,1,13,0,0],[17,1,9,0,0]],
    [[10,1,34,0,0],[16,1,28,0,0],[22,1,22,0,0],[28,1,16,0,0]],
    [[15,1,55,0,0],[26,1,44,0,0],[18,2,17,0,0],[22,2,13,0,0]],
    [[20,1,80,0,0],[18,2,32,0,0],[26,2,24,0,0],[16,4,9,0,0]],
    [[26,1,108,0,0],[24,2,43,0,0],[18,2,15,2,16],[22,2,11,2,12]],
    [[18,2,68,0,0],[16,4,27,0,0],[24,4,19,0,0],[28,4,15,0,0]],
    [[20,2,78,0,0],[18,4,31,0,0],[18,2,14,4,15],[26,4,13,1,14]],
    [[24,2,97,0,0],[22,2,38,2,39],[22,4,18,2,19],[26,4,14,2,15]],
    [[30,2,116,0,0],[22,3,36,2,37],[20,4,16,4,17],[24,4,12,4,13]],
    [[18,2,68,2,69],[26,4,43,1,44],[24,6,19,2,20],[28,6,15,2,16]],
    [[20,4,81,0,0],[30,1,50,4,51],[28,4,22,4,23],[24,3,12,8,13]],
    [[24,2,92,2,93],[22,6,36,2,37],[26,4,20,6,21],[28,7,14,4,15]],
    [[26,4,107,0,0],[22,8,37,1,38],[24,8,20,4,21],[22,12,11,4,12]],
    [[30,3,115,1,116],[24,4,40,5,41],[20,11,16,5,17],[24,11,12,5,13]],
    [[22,5,87,1,88],[24,5,41,5,42],[30,5,24,7,25],[24,11,12,7,13]]
];

/* Alignment pattern center positions per version */
var ALIGN_POS = [
    null,
    [], [6,18], [6,22], [6,26], [6,30], [6,34],
    [6,22,38], [6,24,42], [6,26,46], [6,28,50],
    [6,30,54], [6,32,58], [6,34,62],
    [6,26,46,66], [6,26,48,70]
];

/* Character count indicator length for byte mode */
function ccBits(ver) { return ver <= 9 ? 8 : 16; }

/* Total data codewords for a version/level */
function totalDataCW(ver, lv) {
    var b = EC_BLOCKS[ver][lv];
    return b[1] * b[2] + b[3] * b[4];
}

/* ===========================================================================
 * UTF-8 Encoding
 * =========================================================================== */

function toUTF8(text) {
    var bytes = [];
    for (var i = 0; i < text.length; i++) {
        var c = text.charCodeAt(i);
        if (c < 0x80) {
            bytes.push(c);
        } else if (c < 0x800) {
            bytes.push(0xC0 | (c >> 6), 0x80 | (c & 0x3F));
        } else if (c >= 0xD800 && c < 0xDC00 && i + 1 < text.length) {
            var lo = text.charCodeAt(++i);
            var cp = ((c - 0xD800) << 10) + (lo - 0xDC00) + 0x10000;
            bytes.push(0xF0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3F),
                       0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F));
        } else {
            bytes.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F));
        }
    }
    return bytes;
}

/* ===========================================================================
 * Data Encoding (Byte Mode)
 * =========================================================================== */

function selectVersion(byteLen, lv) {
    for (var v = 1; v < EC_BLOCKS.length; v++) {
        var cap = Math.floor((totalDataCW(v, lv) * 8 - 4 - ccBits(v)) / 8);
        if (cap >= byteLen) return v;
    }
    throw new Error('Data too long for supported QR versions (max V' +
                    (EC_BLOCKS.length - 1) + ' with this EC level)');
}

function encodeData(utf8, ver, lv) {
    var total = totalDataCW(ver, lv);
    var bits = [];

    function push(val, count) {
        for (var i = count - 1; i >= 0; i--) bits.push((val >> i) & 1);
    }

    /* Mode indicator: Byte = 0100 */
    push(4, 4);
    /* Character count (byte count for byte mode) */
    push(utf8.length, ccBits(ver));
    /* Data bytes */
    for (var i = 0; i < utf8.length; i++) push(utf8[i], 8);
    /* Terminator */
    var tLen = Math.min(4, total * 8 - bits.length);
    push(0, tLen);
    /* Byte-align */
    while (bits.length & 7) bits.push(0);
    /* Pad codewords */
    var pads = [0xEC, 0x11], pi = 0;
    while (bits.length < total * 8) { push(pads[pi], 8); pi ^= 1; }

    /* Convert to bytes */
    var out = new Uint8Array(total);
    for (var i = 0; i < total; i++) {
        var byte = 0;
        for (var b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
        out[i] = byte;
    }
    return out;
}

/* ===========================================================================
 * EC Generation & Codeword Interleaving
 * =========================================================================== */

function buildCodewords(data, ver, lv) {
    var b = EC_BLOCKS[ver][lv];
    var ecPer = b[0];

    /* Split data into blocks */
    var blocks = [], off = 0;
    for (var g = 0; g < 2; g++) {
        var cnt = b[1 + g * 2], sz = b[2 + g * 2];
        for (var i = 0; i < cnt; i++) {
            blocks.push(data.slice(off, off + sz));
            off += sz;
        }
    }

    /* EC per block */
    var ecBlocks = [];
    for (var i = 0; i < blocks.length; i++) ecBlocks.push(rsEncode(blocks[i], ecPer));

    /* Interleave data */
    var result = [];
    var maxD = 0;
    for (var i = 0; i < blocks.length; i++) {
        if (blocks[i].length > maxD) maxD = blocks[i].length;
    }
    for (var i = 0; i < maxD; i++) {
        for (var j = 0; j < blocks.length; j++) {
            if (i < blocks[j].length) result.push(blocks[j][i]);
        }
    }

    /* Interleave EC */
    for (var i = 0; i < ecPer; i++) {
        for (var j = 0; j < ecBlocks.length; j++) result.push(ecBlocks[j][i]);
    }

    return result;
}

/* ===========================================================================
 * Matrix Construction
 * =========================================================================== */

function makeMatrix(ver) {
    var size = ver * 4 + 17;
    var mod = [], res = [];
    for (var i = 0; i < size; i++) {
        mod.push(new Uint8Array(size));
        res.push(new Uint8Array(size));
    }
    return { size: size, mod: mod, res: res };
}

function setMod(m, r, c, dark) {
    if (r >= 0 && r < m.size && c >= 0 && c < m.size) {
        m.mod[r][c] = dark ? 1 : 0;
        m.res[r][c] = 1;
    }
}

function placeFinder(m, row, col) {
    for (var r = -1; r <= 7; r++) {
        for (var c = -1; c <= 7; c++) {
            var onEdge = (r === 0 || r === 6 || c === 0 || c === 6);
            var inner  = (r >= 2 && r <= 4 && c >= 2 && c <= 4);
            var sep    = (r < 0 || r > 6 || c < 0 || c > 6);
            setMod(m, row + r, col + c, (onEdge || inner) && !sep);
        }
    }
}

function placeAlign(m, ver) {
    var pos = ALIGN_POS[ver];
    if (!pos || !pos.length) return;
    for (var pi = 0; pi < pos.length; pi++) {
        for (var pj = 0; pj < pos.length; pj++) {
            var cr = pos[pi], cc = pos[pj];
            /* Skip if overlapping finder patterns */
            if (cr <= 8 && cc <= 8) continue;
            if (cr <= 8 && cc >= m.size - 8) continue;
            if (cr >= m.size - 8 && cc <= 8) continue;
            for (var r = -2; r <= 2; r++) {
                for (var c = -2; c <= 2; c++) {
                    var dark = (r === -2 || r === 2 || c === -2 || c === 2 || (r === 0 && c === 0));
                    setMod(m, cr + r, cc + c, dark);
                }
            }
        }
    }
}

function placeTiming(m) {
    for (var i = 8; i < m.size - 8; i++) {
        var dark = (i & 1) === 0;
        if (!m.res[6][i]) setMod(m, 6, i, dark);
        if (!m.res[i][6]) setMod(m, i, 6, dark);
    }
}

function reserveFormat(m) {
    for (var i = 0; i <= 8; i++) {
        if (!m.res[8][i]) { m.res[8][i] = 1; }
        if (!m.res[i][8]) { m.res[i][8] = 1; }
    }
    for (var i = 0; i < 7; i++) m.res[m.size - 1 - i][8] = 1;
    for (var i = 0; i < 8; i++) m.res[8][m.size - 1 - i] = 1;
    /* Dark module (always dark) */
    m.mod[m.size - 8][8] = 1;
    m.res[m.size - 8][8] = 1;
}

function reserveVersion(m, ver) {
    if (ver < 7) return;
    for (var i = 0; i < 18; i++) {
        var r = (i / 3) | 0, c = i % 3;
        m.res[m.size - 11 + c][r] = 1;
        m.res[r][m.size - 11 + c] = 1;
    }
}

function placeDataBits(m, codewords) {
    var bits = [];
    for (var i = 0; i < codewords.length; i++) {
        for (var b = 7; b >= 0; b--) bits.push((codewords[i] >> b) & 1);
    }

    var idx = 0;
    var col = m.size - 1;
    var up = true;

    while (col >= 0) {
        if (col === 6) col--;

        for (var i = 0; i < m.size; i++) {
            var row = up ? (m.size - 1 - i) : i;
            /* Right column of pair */
            if (!m.res[row][col]) {
                m.mod[row][col] = idx < bits.length ? bits[idx++] : 0;
            }
            /* Left column of pair */
            if (col > 0 && !m.res[row][col - 1]) {
                m.mod[row][col - 1] = idx < bits.length ? bits[idx++] : 0;
            }
        }

        up = !up;
        col -= 2;
    }
}

/* ===========================================================================
 * Format & Version Info (BCH codes)
 * =========================================================================== */

var EC_FMT = [1, 0, 3, 2]; /* L, M, Q, H → format bits */

function calcFormatInfo(lv, mask) {
    var d = (EC_FMT[lv] << 3) | mask;
    var bits = d << 10;
    for (var i = 14; i >= 10; i--) {
        if (bits & (1 << i)) bits ^= (0x537 << (i - 10));
    }
    return ((d << 10) | bits) ^ 0x5412;
}

function writeFormatInfo(mod, size, lv, mask) {
    var info = calcFormatInfo(lv, mask);

    /* Region 1: near top-left finder */
    var r1 = [[8,0],[8,1],[8,2],[8,3],[8,4],[8,5],[8,7],[8,8],
              [7,8],[5,8],[4,8],[3,8],[2,8],[1,8],[0,8]];

    /* Region 2: near bottom-left & top-right finders */
    var s = size;
    var r2 = [[s-1,8],[s-2,8],[s-3,8],[s-4,8],[s-5,8],[s-6,8],[s-7,8],
              [8,s-8],[8,s-7],[8,s-6],[8,s-5],[8,s-4],[8,s-3],[8,s-2],[8,s-1]];

    for (var i = 0; i < 15; i++) {
        var bit = (info >> (14 - i)) & 1;
        mod[r1[i][0]][r1[i][1]] = bit;
        mod[r2[i][0]][r2[i][1]] = bit;
    }
}

function calcVersionInfo(ver) {
    var bits = ver << 12;
    for (var i = 17; i >= 12; i--) {
        if (bits & (1 << i)) bits ^= (0x1F25 << (i - 12));
    }
    return (ver << 12) | bits;
}

function writeVersionInfo(mod, size, ver) {
    if (ver < 7) return;
    var info = calcVersionInfo(ver);
    for (var i = 0; i < 18; i++) {
        var bit = (info >> i) & 1;
        var r = (i / 3) | 0, c = i % 3;
        mod[size - 11 + c][r] = bit;
        mod[r][size - 11 + c] = bit;
    }
}

/* ===========================================================================
 * Masking & Penalty Scoring
 * =========================================================================== */

var MASK_FN = [
    function(r, c) { return ((r + c) & 1) === 0; },
    function(r, c) { return (r & 1) === 0; },
    function(r, c) { return c % 3 === 0; },
    function(r, c) { return (r + c) % 3 === 0; },
    function(r, c) { return (((r >> 1) + ((c / 3) | 0)) & 1) === 0; },
    function(r, c) { return ((r * c) % 2 + (r * c) % 3) === 0; },
    function(r, c) { return (((r * c) % 2 + (r * c) % 3) & 1) === 0; },
    function(r, c) { return (((r + c) % 2 + (r * c) % 3) & 1) === 0; }
];

function penaltyScore(mod, size) {
    var score = 0;
    var r, c, run, j, k;

    /* Rule 1: runs of 5+ same-colour in row/column */
    for (r = 0; r < size; r++) {
        run = 1;
        for (c = 1; c < size; c++) {
            if (mod[r][c] === mod[r][c - 1]) { run++; }
            else { if (run >= 5) score += run - 2; run = 1; }
        }
        if (run >= 5) score += run - 2;
    }
    for (c = 0; c < size; c++) {
        run = 1;
        for (r = 1; r < size; r++) {
            if (mod[r][c] === mod[r - 1][c]) { run++; }
            else { if (run >= 5) score += run - 2; run = 1; }
        }
        if (run >= 5) score += run - 2;
    }

    /* Rule 2: 2x2 blocks of same colour */
    for (r = 0; r < size - 1; r++) {
        for (c = 0; c < size - 1; c++) {
            var v = mod[r][c];
            if (v === mod[r][c+1] && v === mod[r+1][c] && v === mod[r+1][c+1]) {
                score += 3;
            }
        }
    }

    /* Rule 3: finder-like patterns (1011101 0000 or 0000 1011101) */
    var p1 = [1,0,1,1,1,0,1,0,0,0,0];
    var p2 = [0,0,0,0,1,0,1,1,1,0,1];
    for (r = 0; r < size; r++) {
        for (c = 0; c <= size - 11; c++) {
            var m1 = true, m2 = true;
            for (k = 0; k < 11; k++) {
                if (mod[r][c + k] !== p1[k]) m1 = false;
                if (mod[r][c + k] !== p2[k]) m2 = false;
                if (!m1 && !m2) break;
            }
            if (m1 || m2) score += 40;
        }
    }
    for (c = 0; c < size; c++) {
        for (r = 0; r <= size - 11; r++) {
            var m1 = true, m2 = true;
            for (k = 0; k < 11; k++) {
                if (mod[r + k][c] !== p1[k]) m1 = false;
                if (mod[r + k][c] !== p2[k]) m2 = false;
                if (!m1 && !m2) break;
            }
            if (m1 || m2) score += 40;
        }
    }

    /* Rule 4: dark module ratio */
    var dark = 0, total = size * size;
    for (r = 0; r < size; r++) {
        for (c = 0; c < size; c++) { if (mod[r][c]) dark++; }
    }
    var pct = (dark * 100) / total;
    score += Math.floor(Math.abs(pct - 50) / 5) * 10;

    return score;
}

/* ===========================================================================
 * QR Code Generation (main pipeline)
 * =========================================================================== */

function generateQR(text, ecLevel) {
    if (typeof ecLevel === 'undefined') ecLevel = EC_H;

    var utf8 = toUTF8(text);
    var ver = selectVersion(utf8.length, ecLevel);
    var data = encodeData(utf8, ver, ecLevel);
    var cw = buildCodewords(data, ver, ecLevel);

    /* Build base matrix with all function patterns */
    var m = makeMatrix(ver);
    placeFinder(m, 0, 0);
    placeFinder(m, 0, m.size - 7);
    placeFinder(m, m.size - 7, 0);
    placeAlign(m, ver);
    placeTiming(m);
    reserveFormat(m);
    reserveVersion(m, ver);

    /* Place data codewords */
    placeDataBits(m, cw);

    /* Try all 8 mask patterns, choose lowest penalty */
    var bestMask = 0, bestScore = Infinity, bestMod = null;

    for (var mask = 0; mask < 8; mask++) {
        /* Clone modules */
        var trial = [];
        for (var r = 0; r < m.size; r++) trial.push(new Uint8Array(m.mod[r]));

        /* Apply mask to data cells only */
        for (var r = 0; r < m.size; r++) {
            for (var c = 0; c < m.size; c++) {
                if (!m.res[r][c] && MASK_FN[mask](r, c)) trial[r][c] ^= 1;
            }
        }

        /* Write format & version info */
        writeFormatInfo(trial, m.size, ecLevel, mask);
        writeVersionInfo(trial, m.size, ver);

        var sc = penaltyScore(trial, m.size);
        if (sc < bestScore) {
            bestScore = sc;
            bestMask = mask;
            bestMod = trial;
        }
    }

    return { modules: bestMod, size: m.size, version: ver, mask: bestMask };
}

/* ===========================================================================
 * SVG Rendering
 * =========================================================================== */

function toSVG(text, opts) {
    opts = opts || {};
    var ecLevel = EC_H;
    if (opts.ecLevel) {
        var map = { L: EC_L, M: EC_M, Q: EC_Q, H: EC_H };
        if (map[opts.ecLevel] !== undefined) ecLevel = map[opts.ecLevel];
    }

    var qr = generateQR(text, ecLevel);
    var pad  = (opts.padding !== undefined) ? opts.padding : 4;
    var size = opts.size || 256;
    var dark = opts.darkColor  || '#000000';
    var light = opts.lightColor || '#ffffff';
    var total = qr.size + pad * 2;

    /* Build a single <path> with run-length-encoded rows */
    var d = '';
    for (var r = 0; r < qr.size; r++) {
        var c = 0;
        while (c < qr.size) {
            if (qr.modules[r][c]) {
                var start = c;
                while (c < qr.size && qr.modules[r][c]) c++;
                var x = start + pad, y = r + pad, w = c - start;
                d += 'M' + x + ' ' + y + 'h' + w + 'v1h-' + w + 'z';
            } else {
                c++;
            }
        }
    }

    return '<svg xmlns="http://www.w3.org/2000/svg"' +
           ' viewBox="0 0 ' + total + ' ' + total + '"' +
           ' width="' + size + '" height="' + size + '"' +
           ' shape-rendering="crispEdges">' +
           '<rect width="' + total + '" height="' + total + '" fill="' + light + '"/>' +
           '<path d="' + d + '" fill="' + dark + '"/>' +
           '</svg>';
}

function render(text, container, opts) {
    container.innerHTML = toSVG(text, opts);
}

/* ===========================================================================
 * Public API
 * =========================================================================== */

var QRCode = {
    toSVG:   toSVG,
    render:  render,
    EC_L: EC_L, EC_M: EC_M, EC_Q: EC_Q, EC_H: EC_H
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = QRCode;
} else {
    exports.QRCode = QRCode;
}

})(typeof window !== 'undefined' ? window : this);
