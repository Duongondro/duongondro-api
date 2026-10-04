// Reads the invite id from the path and the secret from the fragment.
// Nothing here is sent anywhere: the fragment never reaches the server.
(function () {
  "use strict";
  var ID_LEN = 8, SECRET_LEN = 16;
  var ALPHABET = /^[0-9A-HJKMNP-TV-Z]+$/;

  function crockford(s) {
    // Crockford base32 is case-insensitive; I and L read as 1, O reads as 0.
    return s.toUpperCase().replace(/[IL]/g, "1").replace(/O/g, "0");
  }

  function parse() {
    var m = /^\/[if]\/([^\/?#]+)\/?$/i.exec(location.pathname);
    var secret = location.hash.charAt(0) === "#" ? location.hash.slice(1) : "";
    if (!m || !secret) return null;
    var id, sec;
    try { id = crockford(decodeURIComponent(m[1])); sec = crockford(decodeURIComponent(secret)); } catch (e) { return null; }
    if (id.length !== ID_LEN || sec.length !== SECRET_LEN) return null;
    if (!ALPHABET.test(id) || !ALPHABET.test(sec)) return null;
    return id + "-" + sec;
  }

  function $(id) { return document.getElementById(id); }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.setAttribute("aria-hidden", "true");
      ta.setAttribute("class", "offscreen");
      document.body.appendChild(ta);
      ta.select();
      ta.setSelectionRange(0, text.length);
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      ok ? resolve() : reject(new Error("copy failed"));
    });
  }

  function selectCode() {
    var el = $("code"), r = document.createRange();
    r.selectNodeContents(el);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(r);
  }

  function render() {
    var code = parse();
    $(code ? "ok" : "bad").hidden = false;
    $(code ? "bad" : "ok").hidden = true;
    if (!code) return;
    $("code").textContent = code;
    $("copy").onclick = function () {
      var status = $("status");
      copyText(code).then(function () {
        status.textContent = "Copied. Now open the app and paste it.";
      }, function () {
        selectCode();
        status.textContent = "Could not copy automatically. The code is selected: copy it by hand.";
      });
    };
  }

  window.addEventListener("hashchange", render);
  render();
})();
