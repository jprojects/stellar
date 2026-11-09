// Stellar · botón «Copia per a Claude» de la página del informe (templates/default/pages/scan_report.php).
// Va aparte de app.js (núcleo de Quasar) y fuera de la página porque la CSP no permite scripts en línea.
(() => {
  'use strict';
  document.querySelectorAll('[data-stellar-copy]').forEach((btn) => {
    const source = document.getElementById(btn.dataset.stellarCopy);
    if (!source) return;
    btn.hidden = false;
    const label = btn.innerHTML;
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(source.value);
      } catch {
        // Sin permiso de portapapeles (HTTP, navegador antiguo): se selecciona para copiarlo a mano
        source.focus();
        source.select();
        document.execCommand('copy');
      }
      btn.textContent = btn.dataset.copied || '✓';
      setTimeout(() => { btn.innerHTML = label; }, 2000);
    });
  });
})();
