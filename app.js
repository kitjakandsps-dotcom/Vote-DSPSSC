/* =========================================================
   ระบบเลือกตั้งบนเครื่อง (ประธานนักเรียน + ประธานคณะสี)
   โรงเรียนเทพศิรินทร์พุแค สระบุรี · ผู้พัฒนาระบบ: นายนิมิต ศรีวัฒนะ

   app.js — ไฟล์กลางของหน้าบ้าน
   แก้บรรทัดเดียว: EXEC_URL = ลิงก์ /exec ของหลังบ้าน (Apps Script ชุดเลือกตั้งบนเครื่อง)
   ========================================================= */
var EXEC_URL = 'https://script.google.com/macros/s/AKfycbyhe2W-Y_O4VOFYDdUxpVo0lb01SE_GPnJ24uRlQlOK32ploenjCj6UCympY8LIrd8mYA/exec';
/* ไม่ต้องแก้ด้านล่างนี้ */
(function () {
  var TIMEOUT_MS = 30000;

  /** เรียกฟังก์ชันหลังบ้าน (doPost) คืนค่าเป็น Promise */
  function call(fn, args) {
    var ctl = window.AbortController ? new AbortController() : null;
    var timer = ctl ? setTimeout(function () { ctl.abort(); }, TIMEOUT_MS) : null;
    return fetch(EXEC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain;charset=utf-8' },   // ไม่ต้องขออนุญาต CORS ล่วงหน้า
      body: JSON.stringify({ fn: fn, args: args || [] }),
      redirect: 'follow',
      signal: ctl ? ctl.signal : undefined
    }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(function (j) {
      if (timer) clearTimeout(timer);
      if (!j || !j.ok) throw new Error((j && j.error) || 'เซิร์ฟเวอร์ตอบกลับผิดรูปแบบ');
      return j.result;
    }, function (e) {
      if (timer) clearTimeout(timer);
      if (e && e.name === 'AbortError') throw new Error('OFFLINE: หมดเวลารอเซิร์ฟเวอร์');
      if (e instanceof TypeError) throw new Error('OFFLINE: เชื่อมต่อเซิร์ฟเวอร์ไม่ได้');
      throw e;
    });
  }


  /* ---------- รหัสปลดล็อกสำรอง (ใช้ตอนเน็ตหลุด) ----------
     7 หลัก = [ลำดับคณะสี][HMAC-SHA256(กุญแจของจุด, "stid|bid|เลขลำดับ|gid") 6 หลัก]
     เครื่องกรรมการสร้าง · คูหาตรวจเองได้โดยไม่ต้องต่อเน็ต */
  var K256 = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  function utf8(s) {
    if (window.TextEncoder) return new TextEncoder().encode(s);
    var b = unescape(encodeURIComponent(s)), a = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
    return a;
  }
  function sha256(m) {
    var l = m.length, n = ((l + 9 + 63) >> 6) << 6, p = new Uint8Array(n), w = new Array(64);
    p.set(m); p[l] = 0x80;
    var bits = l * 8; p[n - 4] = bits >>> 24 & 255; p[n - 3] = bits >>> 16 & 255; p[n - 2] = bits >>> 8 & 255; p[n - 1] = bits & 255;
    var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    for (var o = 0; o < n; o += 64) {
      for (var i = 0; i < 16; i++) w[i] = p[o + i * 4] << 24 | p[o + i * 4 + 1] << 16 | p[o + i * 4 + 2] << 8 | p[o + i * 4 + 3];
      for (i = 16; i < 64; i++) {
        var x = w[i - 15], y = w[i - 2];
        var s0 = (x >>> 7 | x << 25) ^ (x >>> 18 | x << 14) ^ (x >>> 3), s1 = (y >>> 17 | y << 15) ^ (y >>> 19 | y << 13) ^ (y >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
      for (i = 0; i < 64; i++) {
        var S1 = (e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7), ch = (e & f) ^ (~e & g);
        var t1 = (k + S1 + ch + K256[i] + w[i]) | 0;
        var S0 = (a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10), mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) | 0;
        k = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + k) | 0;
    }
    var out = new Uint8Array(32);
    for (i = 0; i < 8; i++) { out[i * 4] = h[i] >>> 24 & 255; out[i * 4 + 1] = h[i] >>> 16 & 255; out[i * 4 + 2] = h[i] >>> 8 & 255; out[i * 4 + 3] = h[i] & 255; }
    return out;
  }
  function hmac(keyStr, msgStr) {
    var key = utf8(keyStr), msg = utf8(msgStr);
    if (key.length > 64) key = sha256(key);
    var ip = new Uint8Array(64 + msg.length), op = new Uint8Array(96);
    for (var i = 0; i < 64; i++) { var kb = key[i] || 0; ip[i] = kb ^ 0x36; op[i] = kb ^ 0x5c; }
    ip.set(msg, 64); op.set(sha256(ip), 64);
    return sha256(op);
  }
  /** houses = รายการรหัสคณะสี (เรียงตามรหัส) */
  function offCode(key, stid, bid, c, gid, houses) {
    var hi = houses.indexOf(gid) + 1;
    var h = hmac(key, stid + '|' + bid + '|' + c + '|' + gid);
    var n = ((h[0] << 24 >>> 0) + (h[1] << 16) + (h[2] << 8) + h[3]) % 1000000;
    return String(hi) + ('00000' + n).slice(-6);
  }
  /** คูหาตรวจรหัส: คืน { c, gid } หรือ null */
  function offCheck(code, key, stid, bid, base, used, houses) {
    code = String(code || '').replace(/\D/g, '');
    if (code.length !== 7) return null;
    var gid = houses[Number(code.charAt(0)) - 1];
    if (!gid) return null;
    for (var c = Math.max(1, base - 50); c < base + OFF_WINDOW; c++) {
      if (used[c]) continue;
      if (offCode(key, stid, bid, c, gid, houses) === code) return { c: c, gid: gid };
    }
    return null;
  }
  var OFF_WINDOW = 600;

  /* ---------- QR Code (byte mode · แก้ผิดระดับ M · รุ่น 1–10 รองรับลิงก์ยาวถึงราว 210 ตัวอักษร) ---------- */
  var QR_EC = [null, [10, [1, 16]], [16, [1, 28]], [26, [1, 44]], [18, [2, 32]], [24, [2, 43]], [16, [4, 27]], [18, [4, 31]],
    [22, [2, 38], [2, 39]], [22, [3, 36], [2, 37]], [26, [4, 43], [1, 44]]];
  var QR_ALIGN = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];
  function gfMul(x, y) { var z = 0; for (var i = 7; i >= 0; i--) { z = (z << 1) ^ ((z >>> 7) * 0x11D); z ^= ((y >>> i) & 1) * x; } return z & 255; }
  function rsDivisor(deg) {
    var d = []; for (var i = 0; i < deg - 1; i++) d.push(0); d.push(1);
    var root = 1;
    for (i = 0; i < deg; i++) {
      for (var j = 0; j < d.length; j++) { d[j] = gfMul(d[j], root); if (j + 1 < d.length) d[j] ^= d[j + 1]; }
      root = gfMul(root, 2);
    }
    return d;
  }
  function rsRemainder(data, div) {
    var r = div.map(function () { return 0; });
    data.forEach(function (b) { var f = b ^ r.shift(); r.push(0); div.forEach(function (c, i) { r[i] ^= gfMul(c, f); }); });
    return r;
  }
  function qrMatrix(text) {
    var bytes = Array.prototype.slice.call(utf8(text)), ver = 0, ec, dataCW;
    for (var v = 1; v <= 10; v++) {
      ec = QR_EC[v]; dataCW = ec[1][0] * ec[1][1] + (ec[2] ? ec[2][0] * ec[2][1] : 0);
      if (4 + (v < 10 ? 8 : 16) + bytes.length * 8 <= dataCW * 8) { ver = v; break; }
    }
    if (!ver) throw new Error('ข้อความยาวเกินสำหรับ QR');
    // บิตข้อมูล
    var bits = [];
    var put = function (val, len) { for (var i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
    put(4, 4); put(bytes.length, ver < 10 ? 8 : 16); bytes.forEach(function (b) { put(b, 8); });
    put(0, Math.min(4, dataCW * 8 - bits.length));
    while (bits.length % 8) bits.push(0);
    var data = []; for (var i = 0; i < bits.length; i += 8) { var b = 0; for (var k = 0; k < 8; k++) b = b << 1 | bits[i + k]; data.push(b); }
    for (var pad = 0xEC; data.length < dataCW; pad ^= 0xEC ^ 0x11) data.push(pad);
    // แบ่งบล็อก + Reed-Solomon + สลับลำดับ
    var div = rsDivisor(ec[0]), blocks = [], pos = 0;
    [ec[1], ec[2]].forEach(function (g) { if (!g) return; for (var n = 0; n < g[0]; n++) { var d = data.slice(pos, pos + g[1]); pos += g[1]; blocks.push({ d: d, e: rsRemainder(d, div) }); } });
    var cw = [], maxD = Math.max.apply(null, blocks.map(function (x) { return x.d.length; }));
    for (i = 0; i < maxD; i++) blocks.forEach(function (x) { if (i < x.d.length) cw.push(x.d[i]); });
    for (i = 0; i < ec[0]; i++) blocks.forEach(function (x) { cw.push(x.e[i]); });
    // วางลวดลายคงที่
    var size = 17 + 4 * ver, m = [], fn = [];
    for (i = 0; i < size; i++) { m.push(new Array(size).fill(false)); fn.push(new Array(size).fill(false)); }
    var set = function (x, y, dark) { m[y][x] = dark; fn[y][x] = true; };
    for (i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
    [[3, 3], [size - 4, 3], [3, size - 4]].forEach(function (c) {
      for (var dy = -4; dy <= 4; dy++) for (var dx = -4; dx <= 4; dx++) {
        var x = c[0] + dx, y = c[1] + dy, dist = Math.max(Math.abs(dx), Math.abs(dy));
        if (x >= 0 && x < size && y >= 0 && y < size) set(x, y, dist !== 2 && dist !== 4);
      }
    });
    var al = QR_ALIGN[ver];
    al.forEach(function (ax, ia) { al.forEach(function (ay, ib) {
      if ((ia === 0 && ib === 0) || (ia === 0 && ib === al.length - 1) || (ia === al.length - 1 && ib === 0)) return;
      for (var dy = -2; dy <= 2; dy++) for (var dx = -2; dx <= 2; dx++) set(ax + dx, ay + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }); });
    var drawFormat = function (mask) {
      var d = (0 << 3) | mask, r = d;   // ระดับ M = 00
      for (var t = 0; t < 10; t++) r = (r << 1) ^ ((r >>> 9) * 0x537);
      var f = ((d << 10) | r) ^ 0x5412, bit = function (n) { return ((f >>> n) & 1) === 1; };
      for (var q = 0; q <= 5; q++) set(8, q, bit(q));
      set(8, 7, bit(6)); set(8, 8, bit(7)); set(7, 8, bit(8));
      for (q = 9; q < 15; q++) set(14 - q, 8, bit(q));
      for (q = 0; q < 8; q++) set(size - 1 - q, 8, bit(q));
      for (q = 8; q < 15; q++) set(8, size - 15 + q, bit(q));
      set(8, size - 8, true);
    };
    drawFormat(0);
    if (ver >= 7) {
      var r = ver; for (i = 0; i < 12; i++) r = (r << 1) ^ ((r >>> 11) * 0x1F25);
      var vb = ver << 12 | r;
      for (i = 0; i < 18; i++) { var dk = ((vb >>> i) & 1) === 1, a = size - 11 + i % 3, bb = Math.floor(i / 3); set(a, bb, dk); set(bb, a, dk); }
    }
    // วางข้อมูลแบบซิกแซก
    var bi = 0;
    for (var right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (var vert = 0; vert < size; vert++) for (var j = 0; j < 2; j++) {
        var x = right - j, y = ((right + 1) & 2) === 0 ? size - 1 - vert : vert;
        if (!fn[y][x] && bi < cw.length * 8) { m[y][x] = ((cw[bi >>> 3] >>> (7 - (bi & 7))) & 1) === 1; bi++; }
      }
    }
    // เลือก mask ที่คะแนนโทษน้อยที่สุด
    var MASK = [function (x, y) { return (x + y) % 2 === 0; }, function (x, y) { return y % 2 === 0; }, function (x) { return x % 3 === 0; },
      function (x, y) { return (x + y) % 3 === 0; }, function (x, y) { return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; },
      function (x, y) { return x * y % 2 + x * y % 3 === 0; }, function (x, y) { return (x * y % 2 + x * y % 3) % 2 === 0; },
      function (x, y) { return ((x + y) % 2 + x * y % 3) % 2 === 0; }];
    var applyMask = function (k) { for (var y = 0; y < size; y++) for (var x = 0; x < size; x++) if (!fn[y][x] && MASK[k](x, y)) m[y][x] = !m[y][x]; };
    var penalty = function () {
      var p = 0, dark = 0, line, run, x, y;
      for (var dir = 0; dir < 2; dir++) for (var a = 0; a < size; a++) {
        run = 1; line = '';
        for (var c = 0; c < size; c++) {
          var cur = dir ? m[c][a] : m[a][c]; line += cur ? '1' : '0';
          if (c && cur === (dir ? m[c - 1][a] : m[a][c - 1])) { run++; if (run === 5) p += 3; else if (run > 5) p++; } else run = 1;
        }
        p += 40 * ((line.match(/(?=1011101(0000|$))|(?=(^|0000)1011101)/g) || []).length);
      }
      for (y = 0; y < size - 1; y++) for (x = 0; x < size - 1; x++) { var c0 = m[y][x]; if (c0 === m[y][x + 1] && c0 === m[y + 1][x] && c0 === m[y + 1][x + 1]) p += 3; }
      for (y = 0; y < size; y++) for (x = 0; x < size; x++) if (m[y][x]) dark++;
      return p + Math.floor(Math.abs(dark * 20 - size * size * 10) / (size * size)) * 10;
    };
    var best = 0, bestP = Infinity;
    for (k = 0; k < 8; k++) { applyMask(k); drawFormat(k); var pp = penalty(); if (pp < bestP) { bestP = pp; best = k; } applyMask(k); }
    applyMask(best); drawFormat(best);
    return m;
  }
  /** QR เป็น SVG (ขอบเงียบ 4 ช่อง) */
  function qrSvg(text, color) {
    var m = qrMatrix(text), n = m.length, q = 4, d = '';
    for (var y = 0; y < n; y++) for (var x = 0; x < n; x++) if (m[y][x]) d += 'M' + (x + q) + ' ' + (y + q) + 'h1v1h-1z';
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + (n + 2 * q) + ' ' + (n + 2 * q) + '" shape-rendering="crispEdges" role="img" aria-label="QR Code">' +
      '<rect width="100%" height="100%" fill="#fff"/><path fill="' + (color || '#000') + '" d="' + d + '"/></svg>';
  }

  window.EV = {
    call: call,
    ready: !!EXEC_URL && !/ใส่รหัส/.test(EXEC_URL),
    roles: [
      { file: 'desk.html', name: 'เครื่องกรรมการ', hint: 'ตรวจตัวตนและปลดล็อกคูหา' },
      { file: 'booth.html', name: 'คูหาเลือกตั้ง', hint: 'เครื่องที่นักเรียนใช้ลงคะแนน' },
      { file: 'display.html', name: 'จอแสดงผล', hint: 'ยอดผู้มาใช้สิทธิ์และประกาศผล' },
      { file: 'admin.html', name: 'ผู้ดูแลระบบ', hint: 'ตั้งค่า รายชื่อ ผู้สมัคร รายงาน' }
    ],
    qrMatrix: qrMatrix, qrSvg: qrSvg,
    offCode: offCode, offCheck: offCheck, hmacHex: function (k, m) { return Array.prototype.map.call(hmac(k, m), function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); },
    esc: function (s) {
      return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; });
    },
    fmt: function (n) { return Number(n || 0).toLocaleString('th-TH'); },
    /** สีตัวอักษรบนพื้นสี (สีอ่อนใช้ตัวอักษรเข้ม) */
    onColor: function (hex) {
      var m = /^#?([0-9a-f]{6})$/i.exec(hex || ''); if (!m) return '#fff';
      var n = parseInt(m[1], 16), r = n >> 16 & 255, g = n >> 8 & 255, b = n & 255;
      return (0.299 * r + 0.587 * g + 0.114 * b) > 165 ? '#1d1a0a' : '#fff';
    },
    store: {
      get: function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
      set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) {} },
      del: function (k) { try { localStorage.removeItem(k); } catch (e) {} }
    }
  };
})();
