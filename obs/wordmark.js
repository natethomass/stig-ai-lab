/* Channel wordmark.

   Defaults to TECHFITDAD with FIT in the brand colour. Override per source:
     ?brandname=TECHFITDAD   the full wordmark text
     ?accent=FIT             the substring painted in the brand colour
     ?mark=TF                the two-letter block, or ?logo=logo.png for an image
     ?tagline=Homelab · Security+   optional line after a divider
   Pass ?wordmark=off to hide it entirely. */
(function (w) {
  w.renderWordmark = function (host) {
    if (!host || P('wordmark', 'on') === 'off') { if (host) host.style.display = 'none'; return; }

    var name   = P('brandname', 'TECHFITDAD');
    var accent = P('accent', 'FIT');
    var logo   = P('logo', '');
    var mark   = P('mark', 'TF');
    var tag    = P('tagline', '');

    var i = accent ? name.toUpperCase().indexOf(accent.toUpperCase()) : -1;
    var text = i < 0
      ? esc(name)
      : esc(name.slice(0, i)) + '<b>' + esc(name.slice(i, i + accent.length)) + '</b>' +
        esc(name.slice(i + accent.length));

    host.className = 'wordmark';
    host.innerHTML =
      (logo ? '<img class="mark" src="' + esc(logo) + '" alt="">'
            : '<span class="mark">' + esc(mark) + '</span>') +
      '<span>' + text + '</span>' +
      (tag ? '<span class="tag">' + esc(tag) + '</span>' : '');
  };

  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (ch) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch];
    });
  }
})(window);
