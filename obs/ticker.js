/* Seamless marquee.

   Repeat the items until one cycle is at least as wide as the viewport, measure
   that cycle, then clone it once and translate by exactly -50%. Each item owns
   its trailing margin (rather than the track using `gap`) so the cycle width is
   exactly additive — that is what keeps the loop from drifting. Speed is held
   constant in px/sec no matter how much text is passed in. */
(function (w) {
  w.fillTicker = function (track, items, pxPerSec) {
    if (!items || !items.length) return;

    function addSet() {
      items.forEach(function (t) {
        var s = document.createElement('span');
        s.textContent = t;
        track.appendChild(s);
      });
    }

    addSet();
    var guard = 0;
    while (track.scrollWidth < w.innerWidth && guard++ < 30) addSet();

    var cycle = track.scrollWidth;
    Array.prototype.slice.call(track.children).forEach(function (n) {
      track.appendChild(n.cloneNode(true));
    });

    track.style.setProperty('--mq', (cycle / (pxPerSec || 70)).toFixed(2) + 's');
  };
})(window);
