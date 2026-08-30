/* Tiny query-string helper shared by every overlay.
   Usage in OBS: uncheck "Local file" and paste a full URL with params, e.g.
   file:///home/you/stig-ai-lab/obs/lower-third.html?name=Nate&title=STIG%20AI%20Lab */
(function (w) {
  var q = new URLSearchParams(w.location.search);
  w.P = function (key, fallback) {
    var v = q.get(key);
    return (v === null || v === '') ? fallback : v;
  };
  w.PN = function (key, fallback) {
    var v = parseFloat(q.get(key));
    return isNaN(v) ? fallback : v;
  };
  w.PL = function (key, fallback) {
    var v = q.get(key);
    return v ? v.split('|').map(function (s) { return s.trim(); }).filter(Boolean) : fallback;
  };
  /* Write text into every [data-p="key"] node from ?key=... */
  w.bindText = function (map) {
    Object.keys(map).forEach(function (k) {
      document.querySelectorAll('[data-p="' + k + '"]').forEach(function (n) {
        n.textContent = map[k];
      });
    });
  };
})(window);
