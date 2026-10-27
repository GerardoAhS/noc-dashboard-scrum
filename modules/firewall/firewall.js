// Módulo Firewall (Equipo 4). Todo va dentro de una IIFE porque app.js
// vuelve a cargar este script cada vez que se entra al módulo.
(function () {
  const KEY = 'noc.firewall.rules';
  const MAX_SOURCE = 40;
  let rules = [];
  let filter = 'ALL';
  let query = '';

  const $ = (id) => document.getElementById(id);
  const esc = (v) =>
    String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const norm = (v) => String(v).trim().toLowerCase();

  // ---------- Datos (el core es la fuente; aquí solo se trabaja sobre una copia) ----------
  function coreRules() {
    return (window.nocData?.firewallRules || []).map((r) => ({ ...r }));
  }

  function loadRules() {
    try {
      const saved = JSON.parse(localStorage.getItem(KEY));
      if (Array.isArray(saved) && saved.every((r) => r && r.action && r.protocol)) return saved;
    } catch (e) {
      /* sin storage o JSON inválido: se usan los datos del core */
    }
    return coreRules();
  }

  function saveRules() {
    try {
      localStorage.setItem(KEY, JSON.stringify(rules));
    } catch (e) {
      /* el storage es opcional */
    }
  }

  // ---------- Lógica de políticas ----------
  const samePort = (a, b) => a === '*' || b === '*' || String(a) === String(b);

  function matches(rule, pkt) {
    return (
      rule.protocol === pkt.protocol &&
      (rule.port === '*' || String(rule.port) === String(pkt.port)) &&
      (norm(rule.source) === 'any' || norm(rule.source) === norm(pkt.source))
    );
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

  function validate(rule) {
    if (!['ALLOW', 'DENY'].includes(rule.action)) return 'La acción debe ser ALLOW o DENY.';
    if (!['TCP', 'UDP', 'ICMP'].includes(rule.protocol)) return 'Protocolo no válido.';
    if (rule.port !== '*') {
      const n = Number(rule.port);
      if (!/^\d+$/.test(String(rule.port)) || n < 1 || n > 65535) return 'El puerto debe ser un número de 1 a 65535 o *.';
    }
    if (!rule.source) return 'El origen no puede estar vacío.';
    if (rule.source.length > MAX_SOURCE || !/^[\w.\-\/:]+$/.test(rule.source))
      return 'Origen no válido: usa letras, números, punto, guion, "/" o ":" (sin espacios).';
    const dup = rules.some(
      (r) =>
        r.action === rule.action &&
        r.protocol === rule.protocol &&
        String(r.port) === String(rule.port) &&
        norm(r.source) === norm(rule.source)
    );
    if (dup) return 'Ya existe una regla idéntica.';
    return '';
  }

  // ---------- Render ----------
  function showMsg(text, ok) {
    const el = $('fw-msg');
    if (!el) return;
    el.textContent = text;
    el.className = 'fw-msg ' + (text ? (ok ? 'ok' : 'error') : '');
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
    const filtering = filter !== 'ALL' || q !== '';
    const rows = rules
      .map((r, i) => ({ r, i }))
      .filter(({ r }) => filter === 'ALL' || r.action === filter)
      .filter(({ r }) => !q || `${r.protocol} ${r.port} ${r.source}`.toLowerCase().includes(q));

    if (!rules.length) {
      list.innerHTML = '<li class="fw-empty">No hay reglas configuradas. Agrega la primera arriba.</li>';
    } else if (!rows.length) {
      list.innerHTML = '<li class="fw-empty">Ninguna regla coincide con el filtro.</li>';
    } else {
      list.innerHTML = rows
        .map(({ r, i }) => {
          const cls = r.action === 'ALLOW' ? 'allow' : 'deny';
          const lock = filtering ? ' disabled title="Quita el filtro para reordenar"' : '';
          return `
        <li class="rule ${cls}" data-index="${i}">
          <span class="rule-order">#${i + 1}</span>
          <span class="rule-desc"><strong>${esc(r.protocol)}</strong> : ${esc(r.port)} / ${esc(r.source)}
            ${isShadowed(i) ? '<em class="rule-shadow" title="Una regla anterior ya cubre este tráfico, por lo que nunca se aplica">Sombreada</em>' : ''}
          </span>
          <button type="button" class="rule-action ${cls}" data-act="toggle" title="Cambiar entre ALLOW y DENY">${esc(r.action)}</button>
          <span class="rule-tools">
            <button type="button" class="fw-icon" data-act="up" aria-label="Subir regla"${lock}${i === 0 ? ' disabled' : ''}>↑</button>
            <button type="button" class="fw-icon" data-act="down" aria-label="Bajar regla"${lock}${i === rules.length - 1 ? ' disabled' : ''}>↓</button>
            <button type="button" class="fw-icon danger" data-act="delete" aria-label="Eliminar regla">✕</button>
          </span>
        </li>`;
        })
        .join('');
    }
    renderStats();
  }

  function commit() {
    saveRules();
    renderList();
  }

  // ---------- Eventos ----------
  function onListClick(e) {
    const btn = e.target.closest('button[data-act]');
    const li = e.target.closest('li[data-index]');
    if (!btn || !li || btn.disabled) return;
    const i = Number(li.dataset.index);
    const act = btn.dataset.act;

    if (act === 'toggle') rules[i].action = rules[i].action === 'ALLOW' ? 'DENY' : 'ALLOW';
    if (act === 'delete') rules.splice(i, 1);
    if (act === 'up' && i > 0) [rules[i - 1], rules[i]] = [rules[i], rules[i - 1]];
    if (act === 'down' && i < rules.length - 1) [rules[i + 1], rules[i]] = [rules[i], rules[i + 1]];
    showMsg('', true);
    commit();
  }

  function onAdd(e) {
    e.preventDefault();
    const protocol = $('fw-protocol').value;
    const rule = {
      id: rules.reduce((m, r) => Math.max(m, Number(r.id) || 0), 0) + 1,
      action: $('fw-action').value,
      protocol,
      port: protocol === 'ICMP' ? '*' : $('fw-port').value.trim(),
      source: $('fw-source').value.trim()
    };
    const error = validate(rule);
    if (error) return showMsg(error, false);
    rules.push(rule);
    $('fw-port').value = '';
    $('fw-source').value = '';
    showMsg(`Regla agregada: ${rule.action} ${rule.protocol} : ${rule.port} / ${rule.source}.`, true);
    commit();
  }

  function onProtocolChange() {
    const icmp = $('fw-protocol').value === 'ICMP';
    $('fw-port').disabled = icmp;
    $('fw-port').value = icmp ? '*' : '';
  }

  function onTest(e) {
    e.preventDefault();
    const out = $('fw-t-result');
    const protocol = $('fw-t-protocol').value;
    const port = protocol === 'ICMP' ? '*' : $('fw-t-port').value.trim();
    const source = $('fw-t-source').value.trim() || 'Any';
    const n = Number(port);
    if (protocol !== 'ICMP' && (!/^\d+$/.test(port) || n < 1 || n > 65535)) {
      out.className = 'fw-result error';
      out.textContent = 'Escribe un puerto válido (1 a 65535) para probar.';
      return;
    }
    const idx = rules.findIndex((r) => matches(r, { protocol, port, source }));
    const pkt = `${esc(protocol)} : ${esc(port)} desde ${esc(source)}`;
    if (idx === -1) {
      out.className = 'fw-result deny';
      out.innerHTML = `<strong>DENY</strong> — ${pkt}. Ninguna regla coincide (denegación implícita).`;
    } else {
      const r = rules[idx];
      out.className = 'fw-result ' + (r.action === 'ALLOW' ? 'allow' : 'deny');
      out.innerHTML = `<strong>${esc(r.action)}</strong> — ${pkt}. Coincide con la regla #${idx + 1}.`;
    }
  }

  function initFirewallModule() {
    if (!$('firewall-rules')) return;
    rules = loadRules();
    filter = 'ALL';
    query = '';

    $('firewall-rules').addEventListener('click', onListClick);
    $('fw-form').addEventListener('submit', onAdd);
    $('fw-protocol').addEventListener('change', onProtocolChange);
    $('fw-test').addEventListener('submit', onTest);
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
    $('fw-reset').addEventListener('click', () => {
      if (!window.confirm('¿Restablecer las reglas a las del core? Se perderán tus cambios.')) return;
      rules = coreRules();
      showMsg('Reglas restablecidas a los datos del core.', true);
      commit();
    });

    renderList();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFirewallModule);
  } else {
    initFirewallModule();
  }
})();
