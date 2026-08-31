/* Brand loader.

   Every scene links theme.css (structure + neutral surfaces) and then this
   script, which injects the brand token layer named by ?brand=. Defaults to
   techfitdad. Must sit in <head> AFTER the theme.css link: the <link> it adds
   is render-blocking there, so the page never flashes un-branded.

   Add a new identity by dropping brands/<name>.css next to the others — copy
   an existing one and change the hex values. */
(function () {
  var m = /[?&]brand=([a-z0-9-]{1,32})/i.exec(location.search);
  var name = m ? m[1].toLowerCase() : 'techfitdad';
  document.head.insertAdjacentHTML(
    'beforeend', '<link rel="stylesheet" href="brands/' + name + '.css">'
  );
})();
