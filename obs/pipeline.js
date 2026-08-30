/* The six phases of the STIG AI Lab run, shared by several overlays.
   Override with ?phases=Scan|Analyse|Approve  and highlight with ?step=2 (1-based). */
(function (w) {
  var DEFAULT = ['Scan', 'Analyse', 'Approve', 'Remediate', 'Apply', 'Validate'];

  w.renderPipe = function (host, step, phases) {
    phases = phases || (w.PL ? PL('phases', DEFAULT) : DEFAULT);
    host.innerHTML = '';
    phases.forEach(function (name, i) {
      if (i) {
        var l = document.createElement('div');
        l.className = 'link' + (i < step ? ' done' : '');
        host.appendChild(l);
      }
      var n = document.createElement('div');
      n.className = 'node' + (i + 1 === step ? ' active' : (i + 1 < step ? ' done' : ''));
      n.innerHTML = '<em>' + String(i + 1).padStart(2, '0') + '</em>' + name;
      host.appendChild(n);
    });
  };
})(window);

/* Compact variant: dots + the active phase name + an n/N counter. */
(function (w) {
  w.renderPipeMini = function (host, step, phases) {
    phases = phases || (w.PL ? PL('phases', ['Scan','Analyse','Approve','Remediate','Apply','Validate']) : []);
    var dots = phases.map(function (_, i) {
      return '<span class="d' + (i + 1 === step ? ' on' : (i + 1 < step ? ' done' : '')) + '"></span>';
    }).join('');
    var name = phases[step - 1] || '';
    host.innerHTML =
      '<span class="dots">' + dots + '</span>' +
      '<span class="lbl">' + name + '</span>' +
      '<span class="count">' + String(step).padStart(2, '0') + '/' +
        String(phases.length).padStart(2, '0') + '</span>';
  };
})(window);
