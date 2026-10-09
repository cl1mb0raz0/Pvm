/*
 * Filters that take several ticks (<details class="multi">, rendered by
 * core/templates/core/partials/multi_select.html): the summary says what is
 * chosen and a click elsewhere closes the menu, as a select would.
 *
 * Delegated on document, so a menu arriving in an HTMX swap works too, and
 * the summary is written server-side as well: without JavaScript the filter
 * still reads correctly, it only stops closing on its own.
 */
(function () {
  function describe(menu) {
    var chosen = menu.querySelector(".chosen");
    if (!chosen) {
      return;
    }
    var ticked = Array.prototype.filter.call(
      menu.querySelectorAll("input[type=checkbox]"),
      function (box) { return box.checked; }
    );
    chosen.textContent = ticked.length === 0 ? "All"
      : ticked.length === 1 ? ticked[0].parentNode.textContent.trim()
      : ticked.length + " Selected";
  }

  function describeAll() {
    document.querySelectorAll("details.multi").forEach(describe);
  }

  document.addEventListener("change", function (event) {
    var menu = event.target.closest ? event.target.closest("details.multi") : null;
    if (menu) {
      describe(menu);
    }
  });

  document.addEventListener("click", function (event) {
    document.querySelectorAll("details.multi[open]").forEach(function (menu) {
      if (!menu.contains(event.target)) {
        menu.removeAttribute("open");
      }
    });
  });

  document.addEventListener("DOMContentLoaded", describeAll);
  describeAll();
})();
