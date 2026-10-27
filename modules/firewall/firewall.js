// Módulo Firewall (Equipo 4) - Día 2.
// Filtros por acción, búsqueda, cambio ALLOW/DENY y detección de reglas sombreadas.
(function () {
  let rules = [];
  let filter = 'ALL';
  let query = '';

  const $ = (id) => document.getElementById(id);
  const esc = (v) =>
    String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const norm = (v) => String(v).trim().toLowerCase();

  // El core es la fuente de datos; aquí solo se trabaja sobre una copia.
  function coreRules() {
    return (window.nocData?.firewallRules || []).map((r) => ({ ...r }));
  }

  // Una regla queda "sombreada" si otra anterior ya cubre todo lo que ella cubriría.
  function isShadowed(index) {
    const r = rules[index];
    return rules.slice(0, index).some(
      (p) =>
        p.protocol === r.protocol &&
        (p.port === '*' || String(p.port) === String(r.port)) &&
        (norm(p.source) === 'any' || norm(p.source) === norm(r.source))
    );
  }

  function renderStats() {
    const allow = rules.filter((r) => r.action === 'ALLOW').length;
    const deny = rules.length - allow;
    const shadowed = rules.filter((_, i) => isShadowed(i)).length;
    $('fw-stats').innerHTML = [
      ['Reglas', rules.length, ''],
      ['ALLOW', allow, 'allow'],
      ['DENY', deny, 'deny'],
      ['Sombreadas', shadowed, shadowed ? 'warn' : '']
    ]
      .map(([label, value, cls]) => `<div class="fw-stat ${cls}"><span>${label}</span><strong>${value}</strong></div>`)
      .join('');
  }

  function renderList() {
    const list = $('firewall-rules');
    const q = norm(query);
    const rows = rules
      .map((r, i) => ({ r, i }))
      .filter(({ r }) => filter === 'ALL' || r.action === filter)
      .filter(({ r }) => !q || `${r.protocol} ${r.port} ${r.source}`.toLowerCase().includes(q));

    if (!rules.length) {
      list.innerHTML = '<li class="fw-empty">No hay reglas configuradas.</li>';
    } else if (!rows.length) {
      list.innerHTML = '<li class="fw-empty">Ninguna regla coincide con el filtro.</li>';
    } else {
      list.innerHTML = rows
        .map(({ r, i }) => {
          const cls = r.action === 'ALLOW' ? 'allow' : 'deny';
          return `
        <li class="rule ${cls}" data-index="${i}">
          <span class="rule-order">#${i + 1}</span>
          <span class="rule-desc"><strong>${esc(r.protocol)}</strong> : ${esc(r.port)} / ${esc(r.source)}
            ${isShadowed(i) ? '<em class="rule-shadow" title="Una regla anterior ya cubre este tráfico, por lo que nunca se aplica">Sombreada</em>' : ''}
          </span>
          <button type="button" class="rule-action ${cls}" data-act="toggle" title="Cambiar entre ALLOW y DENY">${esc(r.action)}</button>
        </li>`;
        })
        .join('');
    }
    renderStats();
  }

  function onListClick(e) {
    const btn = e.target.closest('button[data-act="toggle"]');
    const li = e.target.closest('li[data-index]');
    if (!btn || !li) return;
    const i = Number(li.dataset.index);
    rules[i].action = rules[i].action === 'ALLOW' ? 'DENY' : 'ALLOW';
    renderList();
  }

  function initFirewallModule() {
    if (!$('firewall-rules')) return;
    rules = coreRules();
    filter = 'ALL';
    query = '';

    $('firewall-rules').addEventListener('click', onListClick);
    $('fw-search').addEventListener('input', (e) => {
      query = e.target.value;
      renderList();
    });
    document.querySelectorAll('.fw-chip').forEach((chip) =>
      chip.addEventListener('click', () => {
        filter = chip.dataset.filter;
        document.querySelectorAll('.fw-chip').forEach((c) => c.classList.toggle('active', c === chip));
        renderList();
      })
    );

    renderList();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFirewallModule);
  } else {
    initFirewallModule();
  }
})();
