import { escapeHtml, setStatusMessage } from './helpers.js';

export function createApiKeyController(ctx, deps) {
  let scopeCatalog = [];

  function formatDate(timestamp) {
    if (!timestamp) {
      return '—';
    }
    try {
      return new Date(timestamp * 1000).toLocaleString();
    } catch (error) {
      return '—';
    }
  }

  function isExpired(key) {
    return Boolean(key.expires_at) && key.expires_at * 1000 <= Date.now();
  }

  function updateBaseUrlHint() {
    const hint = ctx.elements.apiBaseUrlHint;
    if (!hint) {
      return;
    }
    const base = `${window.location.origin}/api/v1`;
    hint.innerHTML = `
      <div><strong>Base URL:</strong> <code>${escapeHtml(base)}</code></div>
      <div class="text-muted mt-1">Authenticate with the header <code>Authorization: Bearer &lt;your-key&gt;</code>. The base URL follows however you reach this dashboard (direct IP:port or your reverse-proxy domain).</div>
    `;
  }

  function renderScopeCheckboxes() {
    const container = ctx.elements.apiKeyScopes;
    if (!container) {
      return;
    }
    container.innerHTML = '';
    scopeCatalog.forEach((scope) => {
      const wrapper = document.createElement('div');
      wrapper.className = 'form-check';
      wrapper.innerHTML = `
        <input class="form-check-input api-scope-input" type="checkbox" value="${escapeHtml(scope.id)}" id="apiScope_${escapeHtml(scope.id)}">
        <label class="form-check-label" for="apiScope_${escapeHtml(scope.id)}">
          <code>${escapeHtml(scope.id)}</code> — ${escapeHtml(scope.description)}
        </label>
      `;
      container.appendChild(wrapper);
    });
  }

  function renderKeysList(keys) {
    const list = ctx.elements.apiKeysList;
    if (!list) {
      return;
    }
    if (!keys || keys.length === 0) {
      list.innerHTML = '<div class="text-muted">No API keys yet.</div>';
      return;
    }

    list.innerHTML = '';
    keys.forEach((key) => {
      const expired = isExpired(key);
      const statusBadge = !key.enabled
        ? '<span class="badge bg-secondary">Paused</span>'
        : expired
          ? '<span class="badge bg-danger">Expired</span>'
          : '<span class="badge bg-success">Active</span>';
      const scopeBadges = (key.scopes || [])
        .map((scope) => `<span class="badge bg-light text-dark border me-1">${escapeHtml(scope)}</span>`)
        .join('');
      const toggleLabel = key.enabled ? 'Pause' : 'Resume';
      const toggleClass = key.enabled ? 'btn-outline-warning' : 'btn-outline-success';

      const wrapper = document.createElement('div');
      wrapper.className = 'mb-2 border rounded p-2';
      wrapper.innerHTML = `
        <div class="d-flex align-items-center justify-content-between flex-wrap gap-2">
          <div>
            <strong>${escapeHtml(key.name)}</strong> ${statusBadge}
            <div class="text-muted small"><code>${escapeHtml(key.key_prefix)}…</code></div>
          </div>
          <div>
            <button class="btn ${toggleClass} btn-sm toggle-api-key-btn" data-key-id="${key.id}" data-enabled="${key.enabled ? '1' : '0'}">${toggleLabel}</button>
            <button class="btn btn-danger btn-sm delete-api-key-btn" data-key-id="${key.id}" data-key-name="${escapeHtml(key.name)}">Delete</button>
          </div>
        </div>
        <div class="mt-2">${scopeBadges || '<span class="text-muted small">No scopes</span>'}</div>
        <div class="text-muted small mt-2">
          Created: ${formatDate(key.created_at)} ·
          Last used: ${formatDate(key.last_used_at)} ·
          Expires: ${key.expires_at ? formatDate(key.expires_at) : 'Never'}
        </div>
      `;
      list.appendChild(wrapper);
    });

    list.querySelectorAll('.toggle-api-key-btn').forEach((button) => {
      button.addEventListener('click', () => toggleKey(button.dataset.keyId, button.dataset.enabled !== '1'));
    });
    list.querySelectorAll('.delete-api-key-btn').forEach((button) => {
      button.addEventListener('click', () => deleteKey(button.dataset.keyId, button.dataset.keyName));
    });
  }

  async function loadApiKeys() {
    const list = ctx.elements.apiKeysList;
    if (list) {
      list.innerHTML = '<div class="text-muted">Loading API keys…</div>';
    }
    updateBaseUrlHint();
    try {
      const response = await fetch('/api/api-keys');
      if (!response.ok) {
        throw new Error('Failed to load API keys');
      }
      const payload = await response.json();
      scopeCatalog = payload.scopes || [];
      if (ctx.elements.apiEnabledToggle) {
        ctx.elements.apiEnabledToggle.checked = Boolean(payload.enabled);
      }
      renderScopeCheckboxes();
      renderKeysList(payload.keys || []);
    } catch (error) {
      console.error('Error loading API keys:', error);
      if (list) {
        list.innerHTML = '<div class="text-danger">Error loading API keys.</div>';
      }
    }
  }

  async function handleToggleEnabled() {
    const enabled = Boolean(ctx.elements.apiEnabledToggle?.checked);
    try {
      const response = await fetch('/api/api-keys/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });
      if (!response.ok) {
        throw new Error('toggle failed');
      }
      setStatusMessage(ctx, enabled ? 'External API enabled.' : 'External API disabled.', 'success');
    } catch (error) {
      if (ctx.elements.apiEnabledToggle) {
        ctx.elements.apiEnabledToggle.checked = !enabled;
      }
      setStatusMessage(ctx, 'Could not update API setting.', 'danger');
    }
  }

  async function handleCreateKey(event) {
    event.preventDefault();
    const errorDiv = ctx.elements.apiKeyFormError;
    errorDiv.style.display = 'none';
    errorDiv.textContent = '';

    const name = ctx.elements.apiKeyName.value.trim();
    const scopes = Array.from(ctx.elements.apiKeyScopes.querySelectorAll('.api-scope-input:checked')).map((cb) => cb.value);
    const expiryRaw = ctx.elements.apiKeyExpiryDays.value.trim();

    if (!name) {
      errorDiv.textContent = 'A name is required.';
      errorDiv.style.display = 'block';
      return;
    }
    if (scopes.length === 0) {
      errorDiv.textContent = 'Select at least one permission.';
      errorDiv.style.display = 'block';
      return;
    }

    const body = { name, scopes };
    if (expiryRaw) {
      const days = Number(expiryRaw);
      if (!Number.isFinite(days) || days <= 0) {
        errorDiv.textContent = 'Expiration must be a positive number of days.';
        errorDiv.style.display = 'block';
        return;
      }
      body.expires_in_days = days;
    }

    try {
      const response = await fetch('/api/api-keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.ok) {
        errorDiv.textContent = payload.error || 'Could not create API key.';
        errorDiv.style.display = 'block';
        return;
      }

      ctx.elements.createApiKeyForm.reset();
      revealToken(payload.token);
      loadApiKeys();
    } catch (error) {
      errorDiv.textContent = 'Network error.';
      errorDiv.style.display = 'block';
    }
  }

  function revealToken(token) {
    const reveal = ctx.elements.apiKeyReveal;
    if (!reveal) {
      return;
    }
    ctx.elements.apiKeyRevealValue.value = token;
    reveal.style.display = 'block';
  }

  async function copyToken() {
    const value = ctx.elements.apiKeyRevealValue?.value;
    if (!value) {
      return;
    }
    try {
      await navigator.clipboard.writeText(value);
      setStatusMessage(ctx, 'API key copied to clipboard.', 'success');
    } catch (error) {
      ctx.elements.apiKeyRevealValue.select();
      setStatusMessage(ctx, 'Select and copy the key manually.', 'warning');
    }
  }

  async function toggleKey(keyId, enabled) {
    try {
      const response = await fetch(`/api/api-keys/${encodeURIComponent(keyId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });
      if (!response.ok) {
        throw new Error('toggle failed');
      }
      loadApiKeys();
    } catch (error) {
      setStatusMessage(ctx, 'Could not update API key.', 'danger');
    }
  }

  async function deleteKey(keyId, keyName) {
    const confirmed = await deps.confirmAction({
      title: 'Delete API key',
      message: `Delete API key '${keyName}'? Any client using it will immediately lose access. This cannot be undone.`,
      confirmLabel: 'Delete key',
      cancelLabel: 'Cancel',
      tone: 'danger',
    });
    if (!confirmed) {
      return;
    }
    try {
      const response = await fetch(`/api/api-keys/${encodeURIComponent(keyId)}`, { method: 'DELETE' });
      if (!response.ok) {
        throw new Error('delete failed');
      }
      setStatusMessage(ctx, 'API key deleted.', 'success');
      loadApiKeys();
    } catch (error) {
      setStatusMessage(ctx, 'Could not delete API key.', 'danger');
    }
  }

  function init() {
    if (!ctx.elements.tabApiKeys) {
      return;
    }
    ctx.elements.tabApiKeys.addEventListener('shown.bs.tab', loadApiKeys);
    ctx.elements.apiEnabledToggle?.addEventListener('change', handleToggleEnabled);
    ctx.elements.createApiKeyForm?.addEventListener('submit', handleCreateKey);
    ctx.elements.apiKeyCopyBtn?.addEventListener('click', copyToken);
  }

  return { init, loadApiKeys };
}
