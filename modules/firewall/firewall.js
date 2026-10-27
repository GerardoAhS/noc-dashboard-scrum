// Módulo Firewall (Equipo 4) - Día 1.
// Todo va dentro de una IIFE porque app.js vuelve a cargar este script
// cada vez que se entra al módulo (evita errores por declaraciones repetidas).
(function () {
  function initFirewallModule() {
    const rules = window.nocData?.firewallRules || [];
    const container = document.getElementById('firewall-rules');

    if (!container) return;

    if (!rules.length) {
      container.innerHTML = '<li class="fw-empty">No hay reglas configuradas.</li>';
      return;
    }

    container.innerHTML = rules
      .map((rule, i) => {
        const actionClass = rule.action === 'ALLOW' ? 'allow' : 'deny';
        return `
        <li class="rule ${actionClass}">
          <span class="rule-order">#${i + 1}</span>
          <span class="rule-desc"><strong>${rule.protocol}</strong> : ${rule.port} / ${rule.source}</span>
          <span class="rule-action ${actionClass}">${rule.action}</span>
        </li>`;
      })
      .join('');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFirewallModule);
  } else {
    initFirewallModule();
  }
})();
