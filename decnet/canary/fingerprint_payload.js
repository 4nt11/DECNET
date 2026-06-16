// SPDX-License-Identifier: AGPL-3.0-or-later
// Canary fingerprint payload — the JS that runs inside an opened HTML/SVG
// canary, harvests browser primitives, and beacons the result back to the
// canary worker.  Ported from canary-self-test.html with the rendering UI
// stripped out.
//
// Three placeholders are substituted by the Python builder BEFORE
// javascript-obfuscator runs:
//
//   {{BEACON_URL}}  → full URL to /c/<callback_token> (no trailing slash)
//   {{MINT_UUID}}   → per-mint UUID, baked into the string-array post-obf
//   {{MINT_NONCE}}  → 16-hex HMAC nonce; the worker rejects ?d=/?o= without it
//
// Beacon strategy (MVP): a bare GET pixel for "I was opened" reliability,
// then a fingerprint payload sent as a base64-URL query param on a second
// GET so the existing worker records the hit even before step-4 POST
// support lands.  Both fail-open: any error short-circuits to next step.

(async function () {
  var BEACON_URL = "{{BEACON_URL}}";
  var MINT_UUID = "{{MINT_UUID}}";
  var MINT_NONCE = "{{MINT_NONCE}}";
  var fp = { mint: MINT_UUID };

  function fire(url) {
    try {
      var img = new Image();
      img.src = url;
    } catch (e) { /* swallow */ }
  }

  // 1) bare-open beacon — fires regardless of whether the rest succeeds
  fire(BEACON_URL + "?o=1&k=" + MINT_NONCE);

  function sha256(str) {
    var buf = new TextEncoder().encode(str);
    return crypto.subtle.digest("SHA-256", buf).then(function (h) {
      return Array.from(new Uint8Array(h))
        .map(function (b) { return b.toString(16).padStart(2, "0"); })
        .join("");
    });
  }

  // navigator
  try {
    fp.nav = {
      ua: navigator.userAgent,
      pl: navigator.platform,
      lg: navigator.language,
      lgs: (navigator.languages || []).join(","),
      ck: navigator.cookieEnabled,
      dnt: navigator.doNotTrack,
      hc: navigator.hardwareConcurrency,
      dm: navigator.deviceMemory || null,
      tp: navigator.maxTouchPoints,
      wd: navigator.webdriver === true,
      pdf: navigator.pdfViewerEnabled || null,
    };
  } catch (e) { fp.nav = { err: String(e) }; }

  // screen
  try {
    fp.scr = {
      w: screen.width, h: screen.height,
      aw: screen.availWidth, ah: screen.availHeight,
      cd: screen.colorDepth, pd: screen.pixelDepth,
      dpr: window.devicePixelRatio,
      iw: window.innerWidth, ih: window.innerHeight,
      or: (screen.orientation && screen.orientation.type) || null,
    };
  } catch (e) { fp.scr = { err: String(e) }; }

  // tz / locale
  try {
    var dtf = Intl.DateTimeFormat().resolvedOptions();
    fp.tz = {
      z: dtf.timeZone, lc: dtf.locale,
      ca: dtf.calendar, ns: dtf.numberingSystem,
      off: new Date().getTimezoneOffset(),
    };
  } catch (e) { fp.tz = { err: String(e) }; }

  // connection
  try {
    var c = navigator.connection;
    fp.cn = c ? {
      t: c.effectiveType, dl: c.downlink, rtt: c.rtt, sd: c.saveData,
    } : null;
  } catch (e) { fp.cn = { err: String(e) }; }

  // canvas
  try {
    var cv = document.createElement("canvas");
    cv.width = 280; cv.height = 60;
    var ctx = cv.getContext("2d");
    ctx.textBaseline = "top";
    ctx.font = "14px Arial";
    ctx.fillStyle = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("c-" + String.fromCharCode(0x1f600), 2, 15);
    ctx.fillStyle = "rgba(102,204,0,0.7)";
    ctx.fillText("c-" + String.fromCharCode(0x1f600), 4, 17);
    var dataURL = cv.toDataURL();
    fp.cv = { h: await sha256(dataURL), n: dataURL.length };
  } catch (e) { fp.cv = { err: String(e) }; }

  // webgl
  try {
    var gc = document.createElement("canvas");
    var gl = gc.getContext("webgl") || gc.getContext("experimental-webgl");
    if (gl) {
      var ext = gl.getExtension("WEBGL_debug_renderer_info");
      fp.gl = {
        v: gl.getParameter(gl.VENDOR),
        r: gl.getParameter(gl.RENDERER),
        ver: gl.getParameter(gl.VERSION),
        sl: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        uv: ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : null,
        ur: ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : null,
      };
    } else { fp.gl = { err: "unavailable" }; }
  } catch (e) { fp.gl = { err: String(e) }; }

  // audio
  try {
    var ACtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (ACtx) {
      var actx = new ACtx(1, 44100, 44100);
      var osc = actx.createOscillator();
      var cmp = actx.createDynamicsCompressor();
      osc.type = "triangle"; osc.frequency.value = 10000;
      cmp.threshold.value = -50; cmp.knee.value = 40;
      cmp.ratio.value = 12; cmp.attack.value = 0; cmp.release.value = 0.25;
      osc.connect(cmp); cmp.connect(actx.destination);
      osc.start(0);
      var buf = await actx.startRendering();
      var data = buf.getChannelData(0).slice(4500, 5000);
      var sum = 0;
      for (var i = 0; i < data.length; i++) sum += Math.abs(data[i]);
      fp.au = { h: await sha256(sum.toString()), s: sum.toFixed(8) };
    } else { fp.au = { err: "unavailable" }; }
  } catch (e) { fp.au = { err: String(e) }; }

  // fonts
  try {
    var bases = ["monospace", "sans-serif", "serif"];
    var tests = [
      "Arial", "Helvetica", "Times New Roman", "Courier New", "Verdana",
      "Georgia", "Trebuchet MS", "Comic Sans MS", "Impact",
      "Calibri", "Cambria", "Consolas", "Segoe UI", "Tahoma",
      "JetBrains Mono", "Fira Code", "Cascadia Code", "SF Mono",
      "Menlo", "Monaco", "Source Code Pro", "Inconsolata", "Hack",
      "San Francisco", "Helvetica Neue", "Lucida Grande",
      "DejaVu Sans", "DejaVu Sans Mono", "Liberation Sans",
      "Liberation Mono", "Ubuntu", "Ubuntu Mono", "Roboto",
      "Noto Sans", "Noto Mono",
      "Microsoft YaHei", "SimSun", "PingFang SC", "Hiragino Sans",
      "Hiragino Kaku Gothic Pro", "Yu Gothic", "Meiryo",
      "Malgun Gothic", "Noto Sans CJK",
      "Adobe Garamond Pro", "Myriad Pro", "Minion Pro",
      "Bahnschrift", "Cyberpunk",
    ];
    var sp = document.createElement("span");
    sp.style.fontSize = "72px";
    sp.style.position = "absolute";
    sp.style.left = "-9999px";
    sp.innerHTML = "mmmmmmmmmmlli";
    document.body.appendChild(sp);
    var bs = {};
    for (var bi = 0; bi < bases.length; bi++) {
      sp.style.fontFamily = bases[bi];
      bs[bases[bi]] = { w: sp.offsetWidth, h: sp.offsetHeight };
    }
    var det = [];
    for (var ti = 0; ti < tests.length; ti++) {
      for (var bj = 0; bj < bases.length; bj++) {
        sp.style.fontFamily = "'" + tests[ti] + "'," + bases[bj];
        if (sp.offsetWidth !== bs[bases[bj]].w ||
            sp.offsetHeight !== bs[bases[bj]].h) {
          det.push(tests[ti]); break;
        }
      }
    }
    document.body.removeChild(sp);
    fp.ft = {
      h: await sha256(det.slice().sort().join(",")),
      n: det.length, t: tests.length, d: det,
    };
  } catch (e) { fp.ft = { err: String(e) }; }

  // webrtc local ip leak
  try {
    var ips = {}; var cands = [];
    var RPC = window.RTCPeerConnection || window.webkitRTCPeerConnection ||
              window.mozRTCPeerConnection;
    if (RPC) {
      var pc = new RPC({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
      pc.createDataChannel("");
      pc.onicecandidate = function (e) {
        if (!e.candidate) return;
        cands.push(e.candidate.candidate);
        var m = e.candidate.candidate.match(
          /(\d+\.\d+\.\d+\.\d+|[a-f0-9:]+::[a-f0-9:]+)/);
        if (m) ips[m[1]] = 1;
      };
      var off = await pc.createOffer();
      await pc.setLocalDescription(off);
      await new Promise(function (r) { setTimeout(r, 1500); });
      pc.close();
      fp.rtc = { ip: Object.keys(ips), n: cands.length, c: cands.slice(0, 3) };
    } else { fp.rtc = { err: "unavailable" }; }
  } catch (e) { fp.rtc = { err: String(e) }; }

  // battery
  try {
    if (navigator.getBattery) {
      var bat = await navigator.getBattery();
      fp.bt = {
        c: bat.charging, l: bat.level,
        ct: bat.chargingTime === Infinity ? "inf" : bat.chargingTime,
        dt: bat.dischargingTime === Infinity ? "inf" : bat.dischargingTime,
      };
    } else { fp.bt = { err: "unavailable" }; }
  } catch (e) { fp.bt = { err: String(e) }; }

  // perf timing jitter
  try {
    var samples = [];
    for (var pi = 0; pi < 1000; pi++) {
      var pa = performance.now();
      var x = 0;
      for (var pj = 0; pj < 1000; pj++) x += Math.sqrt(pj);
      samples.push(performance.now() - pa);
    }
    samples.sort(function (a, b) { return a - b; });
    fp.pf = {
      med: samples[500].toFixed(4),
      p95: samples[950].toFixed(4),
      mn: samples[0].toFixed(4),
      mx: samples[999].toFixed(4),
    };
  } catch (e) { fp.pf = { err: String(e) }; }

  // permissions
  try {
    if (navigator.permissions) {
      var names = ["geolocation", "notifications", "camera", "microphone",
                   "persistent-storage", "clipboard-read", "clipboard-write"];
      var st = {};
      for (var ni = 0; ni < names.length; ni++) {
        try {
          var r = await navigator.permissions.query({ name: names[ni] });
          st[names[ni]] = r.state;
        } catch (e) { st[names[ni]] = "unsupported"; }
      }
      fp.pm = st;
    } else { fp.pm = { err: "unavailable" }; }
  } catch (e) { fp.pm = { err: String(e) }; }

  // composite identity hash — stable inputs only
  try {
    var stable = [
      fp.cv && fp.cv.h, fp.au && fp.au.h, fp.ft && fp.ft.h,
      fp.gl && fp.gl.ur, fp.nav && fp.nav.pl,
      fp.nav && fp.nav.hc, fp.tz && fp.tz.z,
      fp.scr && (fp.scr.w + "x" + fp.scr.h),
    ].filter(Boolean).join("|");
    fp.id = await sha256(stable);
  } catch (e) { fp.id = { err: String(e) }; }

  // 2) ship the payload as base64url JSON on a GET query param.
  //    The current worker records the hit on /c/<slug>; step-4 worker
  //    will decode ?d= and persist the fingerprint blob.
  try {
    var json = JSON.stringify(fp);
    var b64 = btoa(unescape(encodeURIComponent(json)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    // chunk if URL would exceed safe limit (~6KB)
    var MAX = 6000;
    if (b64.length <= MAX) {
      fire(BEACON_URL + "?d=" + b64 + "&k=" + MINT_NONCE);
    } else {
      var sid = (Math.random() * 1e9 | 0).toString(36);
      var total = Math.ceil(b64.length / MAX);
      for (var ci = 0; ci < total; ci++) {
        var part = b64.substr(ci * MAX, MAX);
        fire(BEACON_URL + "?s=" + sid + "&i=" + ci + "&n=" + total + "&d=" + part + "&k=" + MINT_NONCE);
      }
    }
  } catch (e) { /* swallow */ }
})();
