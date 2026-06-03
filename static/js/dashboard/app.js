import { createChartController } from './charts.js';
import { createDashboardContext } from './context.js';
import { createDialogController } from './dialogs.js';
import {
  applyTheme,
  buildProjectSummaries,
  countActiveFilters,
  escapeHtml,
  flashButtonSuccess,
  getInitialTheme,
  matchesQuickFilter,
  setStatusMessage,
  updateQuickFilterUI,
  updateRefreshUi,
  updateSummaryCards,
} from './helpers.js';
import { createMobileController } from './mobile.js';
import { createLogController } from './logs.js';
import { createNotificationController } from './notifications.js';
import { createTableController } from './table.js';
import { createUpdateManagerController } from './updates.js';
import { createUserController } from './users.js';
import { createApiKeyController } from './apikeys.js';

const ctx = createDashboardContext(window.STATAINER_CONFIG || {});
const dialogs = createDialogController(ctx);

if (ctx.elements.appVersionText && ctx.config.appVersion) {
  ctx.elements.appVersionText.textContent = ctx.config.appVersion;
}

function patchFetchWithCsrf() {
  const originalFetch = window.fetch.bind(window);
  window.fetch = (input, init = {}) => {
    const method = (init.method || (input instanceof Request && input.method) || 'GET').toUpperCase();
    if (['POST', 'PUT', 'DELETE'].includes(method)) {
      const headers = init.headers ||= {};
      headers['X-CSRFToken'] = ctx.config.csrfToken;
    }
    return originalFetch(input, init);
  };
}

const charts = createChartController(ctx);
const logs = createLogController(ctx);
const table = createTableController(ctx, {
  matchesQuickFilter: (item) => matchesQuickFilter(ctx, item),
  fetchMetrics,
  showHistoryChart: (containerId, containerName) => charts.showHistoryChart(containerId, containerName),
  openComparison: (compareType) => charts.openComparison(compareType),
  openLogs: (containerId, containerName) => logs.openLogs(containerId, containerName),
});
const notifications = createNotificationController(ctx);
const users = createUserController(ctx, {
  getAllTableColumns: () => table.getAllTableColumns(),
  confirmAction: (options) => dialogs.confirm(options),
  showNotice: (options) => dialogs.alert(options),
});
const apiKeys = createApiKeyController(ctx, {
  confirmAction: (options) => dialogs.confirm(options),
});
let mobile = null;
const updates = createUpdateManagerController(ctx, {
  confirmAction: (options) => dialogs.confirm(options),
  fetchMetrics,
  closeMobileMenu: () => mobile?.closeSidebarMenu(),
});
mobile = createMobileController(ctx, {
  openSettings: () => users.openSettings(),
  logout: () => logout(),
  toggleTheme: () => toggleTheme(),
  refreshUserInfo: () => users.fetchWhoAmI(),
  renderNotifications: () => notifications.renderNotifList(),
  updateNotificationBadge: () => notifications.updateNotifBadge(),
});

function redirectToLogin() {
  window.location.href = '/login';
}

async function logout() {
  const confirmed = await dialogs.confirm({
    title: 'Log out',
    message: 'Are you sure you want to end the current session?',
    confirmLabel: 'Log out',
    cancelLabel: 'Stay here',
    tone: 'danger',
  });
  if (!confirmed) {
    return;
  }

  try {
    await fetch('/logout', {
      method: 'GET',
      credentials: 'same-origin',
      headers: { 'Cache-Control': 'no-cache, no-store, must-revalidate' },
    });
  } finally {
    redirectToLogin();
    setTimeout(() => window.location.reload(), 100);
  }
}

function toggleTheme() {
  ctx.state.currentTheme = ctx.state.currentTheme === 'light' ? 'dark' : 'light';
  localStorage.setItem('theme', ctx.state.currentTheme);
  applyTheme(ctx, ctx.state.currentTheme);
  charts.refreshOpenCharts();
}

function buildMetricsQuery(extraParams = {}) {
  const query = new URLSearchParams({
    sort: ctx.elements.sortBy.value,
    dir: ctx.elements.sortDir.value,
    source: ctx.elements.metricsSource.value,
    stream_interval: String(ctx.state.refreshIntervalMs),
  });
  if (ctx.elements.filterName.value.trim()) query.set('name', ctx.elements.filterName.value.toLowerCase().trim());
  if (ctx.elements.filterStatus.value) query.set('status', ctx.elements.filterStatus.value);
  if (ctx.elements.filterProject.value) query.set('project', ctx.elements.filterProject.value);
  if (ctx.elements.filterRange.value) query.set('range', ctx.elements.filterRange.value);
  if ((parseInt(ctx.elements.maxItems.value, 10) || 0) > 0) query.set('max', parseInt(ctx.elements.maxItems.value, 10));
  Object.entries(extraParams).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      query.set(key, String(value));
    }
  });
  return query;
}

function formatProjectStatusLabel(status) {
  switch (String(status || '').toLowerCase()) {
    case 'healthy':
      return 'Healthy';
    case 'stopped':
      return 'Stopped';
    default:
      return 'Degraded';
  }
}

function formatProjectMemory(summary) {
  const usage = Number(summary.mem_usage_total) || 0;
  const limit = Number(summary.mem_limit_total) || 0;
  if (limit > 0) {
    const pressure = summary.mem_pressure_percent !== null && summary.mem_pressure_percent !== undefined
      ? ` (${Number(summary.mem_pressure_percent).toFixed(1)}%)`
      : '';
    return `${usage.toFixed(0)} / ${limit.toFixed(0)} MB${pressure}`;
  }
  if (usage > 0) {
    return `${usage.toFixed(0)} MB in use`;
  }
  return 'No RAM limit data';
}

function renderProjectDashboard(projectSummaries) {
  const summaries = Array.isArray(projectSummaries) ? projectSummaries : [];
  ctx.state.projectSummaries = summaries;

  if (!ctx.elements.projectDashboardGrid || !ctx.elements.projectDashboardMeta) {
    return;
  }

  if (summaries.length === 0) {
    ctx.elements.projectDashboardMeta.textContent = 'No Compose stacks detected in the current snapshot.';
    ctx.elements.projectDashboardGrid.innerHTML = '<div class="project-dashboard-empty">No Compose projects match the current metrics scope.</div>';
    return;
  }

  ctx.elements.projectDashboardMeta.textContent = `${summaries.length} Compose stack${summaries.length === 1 ? '' : 's'} in the current snapshot`;
  ctx.elements.projectDashboardGrid.innerHTML = summaries.map((summary) => `
    <article class="project-summary-card" data-project-summary="${escapeHtml(summary.project)}" data-state="${escapeHtml(summary.status)}">
      <div class="project-summary-top">
        <div>
          <p class="project-summary-eyebrow">Compose stack</p>
          <h3 class="project-summary-title">${escapeHtml(summary.project)}</h3>
        </div>
        <span class="project-summary-status" data-state="${escapeHtml(summary.status)}">${formatProjectStatusLabel(summary.status)}</span>
      </div>
      <p class="project-summary-meta">${summary.container_count} container${summary.container_count === 1 ? '' : 's'} • ${summary.running_count} running • ${summary.exited_count} exited</p>
      <div class="project-summary-stats">
        <div class="project-summary-stat">
          <span class="project-summary-label">CPU total</span>
          <strong>${Number(summary.cpu_total || 0).toFixed(1)}%</strong>
        </div>
        <div class="project-summary-stat">
          <span class="project-summary-label">RAM total</span>
          <strong>${escapeHtml(formatProjectMemory(summary))}</strong>
        </div>
        <div class="project-summary-stat">
          <span class="project-summary-label">Updates</span>
          <strong>${summary.update_count}</strong>
        </div>
        <div class="project-summary-stat">
          <span class="project-summary-label">Restarts</span>
          <strong>${summary.restart_count}</strong>
        </div>
      </div>
    </article>
  `).join('');
}

function applyMetricsData(data) {
  if (data?.error === 'auth') {
    redirectToLogin();
    return;
  }

  ctx.state.allMetricsData = Array.isArray(data) ? data : (Array.isArray(data?.rows) ? data.rows : []);
  renderProjectDashboard(Array.isArray(data?.project_summaries) ? data.project_summaries : buildProjectSummaries(ctx.state.allMetricsData));
  const userAllowedColumns = ctx.state.allMetricsData.length > 0 && ctx.state.allMetricsData[0]._allowed_columns
    ? ctx.state.allMetricsData[0]._allowed_columns
    : null;
  if (userAllowedColumns) {
    table.updateColumnCheckboxesForUser(userAllowedColumns);
  }

  updateSummaryCards(ctx, ctx.state.allMetricsData);
  table.populateTable(ctx.state.allMetricsData);
  updates.updateBadgeFromMetrics(ctx.state.allMetricsData);
  ctx.elements.lastRefreshMeta.textContent = `${ctx.state.allMetricsData.length} containers in latest snapshot`;
  ctx.elements.metricsSourceValue.textContent = ctx.elements.metricsSource.selectedOptions[0].textContent;
  ctx.elements.activeFiltersValue.textContent = `${countActiveFilters(ctx)} active filters`;
}

function closeMetricsStream() {
  if (ctx.state.streamReconnectTimer) {
    clearTimeout(ctx.state.streamReconnectTimer);
    ctx.state.streamReconnectTimer = null;
  }
  if (ctx.state.streamSource) {
    ctx.state.streamSource.close();
    ctx.state.streamSource = null;
  }
  ctx.state.streamConnected = false;
}

function scheduleStreamReconnect() {
  if (ctx.state.autoRefreshPaused || ctx.state.streamReconnectTimer) {
    return;
  }
  ctx.state.streamReconnectTimer = setTimeout(() => {
    ctx.state.streamReconnectTimer = null;
    connectMetricsStream();
  }, Math.max(1500, ctx.state.refreshIntervalMs));
}

function connectMetricsStream() {
  closeMetricsStream();
  if (ctx.state.autoRefreshPaused) {
    updateRefreshUi(ctx);
    return;
  }

  const source = new EventSource(`/api/stream?${buildMetricsQuery({ since: ctx.state.lastNotifTimestamp || 0, summary: 1 }).toString()}`);
  ctx.state.streamSource = source;
  ctx.state.streamConnected = false;
  updateRefreshUi(ctx);

  source.addEventListener('connected', () => {
    ctx.state.streamConnected = true;
    updateRefreshUi(ctx);
  });

  source.addEventListener('metrics', (event) => {
    ctx.state.streamConnected = true;
    updateRefreshUi(ctx);
    try {
      applyMetricsData(JSON.parse(event.data));
    } catch (error) {
      console.error('Unable to process SSE metrics payload:', error);
    }
  });

  source.addEventListener('notifications', (event) => {
    try {
      const payload = JSON.parse(event.data);
      notifications.ingestNotifications(payload.items || []);
    } catch (error) {
      console.error('Unable to process SSE notifications payload:', error);
    }
  });

  source.addEventListener('error', (event) => {
    if (event?.data) {
      try {
        const payload = JSON.parse(event.data);
        setStatusMessage(ctx, payload.message || 'Realtime stream error.', 'danger');
      } catch (error) {
        console.error('Unable to process SSE error payload:', error);
      }
    }
  });

  source.onerror = () => {
    closeMetricsStream();
    updateRefreshUi(ctx);
    scheduleStreamReconnect();
  };
}

function restartAutoRefresh() {
  if (ctx.state.autoRefreshPaused) {
    closeMetricsStream();
  } else {
    connectMetricsStream();
  }
  updateRefreshUi(ctx);
}

function setQuickFilter(filterName) {
  ctx.state.currentQuickFilter = filterName || 'all';
  updateQuickFilterUI(ctx);
  table.renderTable(ctx.state.allMetricsData);
}

function resetFilters() {
  ctx.elements.filterName.value = '';
  ctx.elements.filterStatus.value = '';
  ctx.elements.filterProject.value = '';
  ctx.elements.filterRange.value = '86400';
  ctx.elements.sortBy.value = 'combined';
  ctx.elements.sortDir.value = 'desc';
  ctx.elements.maxItems.value = '25';
  ctx.elements.metricsSource.value = 'cadvisor';
  ['filterName', 'filterStatus', 'filterProject', 'filterRange', 'sortBy', 'sortDir', 'maxItems', 'metricsSource']
    .forEach((key) => localStorage.setItem(key, ctx.elements[key].value));
  setQuickFilter('all');
  fetchMetrics();
  restartAutoRefresh();
}

function saveSettings() {
  document.querySelectorAll('.project-toggle').forEach((button) => {
    localStorage.setItem(`projectToggle-${button.dataset.project}`, button.textContent === '[-]' ? 'open' : 'closed');
  });
  ['filterName', 'filterStatus', 'filterProject', 'filterRange', 'sortBy', 'sortDir', 'maxItems', 'refreshInterval', 'metricsSource']
    .forEach((id) => localStorage.setItem(id, ctx.elements[id].value));
  localStorage.setItem('chartType', ctx.state.currentChartType);
  localStorage.setItem('theme', ctx.state.currentTheme);
  localStorage.setItem('serverIP', ctx.elements.serverIP.value);
  localStorage.setItem('useCustomIP', ctx.elements.useCustomIP.checked);
  ctx.elements.columnToggleInputs.forEach((input) => {
    localStorage.setItem(`colVisible-${input.value}`, input.checked);
  });
  localStorage.setItem('notifEnableCPU', ctx.elements.notifEnableCPU.checked);
  localStorage.setItem('notifEnableRAM', ctx.elements.notifEnableRAM.checked);
  localStorage.setItem('notifEnableStatus', ctx.elements.notifEnableStatus.checked);
  localStorage.setItem('notifEnableUpdate', ctx.elements.notifEnableUpdate.checked);
  localStorage.setItem(
    'notifWindowSeconds',
    String(((parseInt(ctx.elements.notifWindowMinutes?.value, 10) || 0) * 60) + (parseInt(ctx.elements.notifWindowSeconds?.value, 10) || 0)),
  );
  flashButtonSuccess(ctx.elements.saveSettingsBtn, { label: 'Saved' });
  setStatusMessage(ctx, 'Settings saved.', 'success');
}

function toggleAllColumns() {
  const anyChecked = ctx.elements.columnToggleInputs.some((input) => !input.disabled && input.checked);
  ctx.elements.columnToggleInputs.forEach((input) => {
    if (!input.disabled) {
      input.checked = !anyChecked;
      localStorage.setItem(`colVisible-${input.value}`, input.checked);
    }
  });
  table.applyColumnVisibility();
}

async function fetchMetrics() {
  if (ctx.state.isFetching) {
    return;
  }
  ctx.state.isFetching = true;
  ctx.elements.tableStatusDiv.textContent = '...';

  try {
    const response = await fetch(`/api/metrics?${buildMetricsQuery({ summary: 1 }).toString()}`, {
      credentials: 'include',
      headers: {
        'Cache-Control': 'no-cache',
        'X-Requested-With': 'XMLHttpRequest',
        'X-CSRFToken': ctx.config.csrfToken,
      },
    });
    if (response.status === 401) {
      redirectToLogin();
      return;
    }
    if (!response.ok) {
      throw new Error(`Network response was not ok: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    if (data?.error === 'auth') {
      redirectToLogin();
      return;
    }

    applyMetricsData(data);
  } catch (error) {
    console.error('Error during fetch or processing:', error);
    ctx.elements.tableStatusDiv.textContent = 'Error loading data. Error during fetch or processing.';
    ctx.elements.tableStatusDiv.style.color = 'red';
    ctx.elements.lastRefreshMeta.textContent = 'Latest refresh failed';
  } finally {
    ctx.state.isFetching = false;
  }
}

function initHeaderSorting() {
  const headerSortMap = {
    name: 'name',
    cpu: 'cpu',
    ram: 'mem',
    gpu: 'gpu_max',
    pid: 'pid_count',
    status: 'status',
    uptime: 'uptime_sec',
    restarts: 'restarts',
    memlimit: 'mem_usage_limit',
    netio: 'net_io_rx',
    blockio: 'block_io_r',
    update: 'update_available',
  };

  document.querySelectorAll('#metricsTable thead th').forEach((header) => {
    const colClass = [...header.classList].find((className) => className.startsWith('col-'));
    if (!colClass) return;
    const key = colClass.replace('col-', '');
    const sortKey = headerSortMap[key];
    if (!sortKey) return;
    header.style.cursor = 'pointer';
    header.addEventListener('click', () => {
      if (ctx.elements.sortBy.value === sortKey) {
        ctx.elements.sortDir.value = ctx.elements.sortDir.value === 'asc' ? 'desc' : 'asc';
      } else {
        ctx.elements.sortBy.value = sortKey;
        ctx.elements.sortDir.value = 'desc';
      }
      localStorage.setItem('sortBy', ctx.elements.sortBy.value);
      localStorage.setItem('sortDir', ctx.elements.sortDir.value);
      fetchMetrics();
      restartAutoRefresh();
    });
  });
}

async function initProjects() {
  const savedProject = localStorage.getItem('filterProject');
  try {
    const response = await fetch('/api/projects', { credentials: 'include' });
    const projects = await response.json();
    ctx.elements.filterProject.innerHTML = '<option value="">All Projects</option>';
    projects.forEach((project) => {
      const option = document.createElement('option');
      option.value = project;
      option.textContent = project;
      ctx.elements.filterProject.appendChild(option);
    });
    if (savedProject) {
      ctx.elements.filterProject.value = savedProject;
    }
  } catch (error) {
    console.error('Error loading projects:', error);
  }
}

function loadPersistedControls() {
  ctx.state.currentTheme = getInitialTheme();
  applyTheme(ctx, ctx.state.currentTheme);

  ctx.elements.filterName.value = localStorage.getItem('filterName') || '';
  ctx.elements.filterStatus.value = localStorage.getItem('filterStatus') || '';
  ctx.elements.filterRange.value = localStorage.getItem('filterRange') || '86400';
  ctx.elements.sortBy.value = localStorage.getItem('sortBy') || 'combined';
  ctx.elements.sortDir.value = localStorage.getItem('sortDir') || 'desc';
  ctx.elements.maxItems.value = localStorage.getItem('maxItems') || '25';
  ctx.elements.serverIP.value = localStorage.getItem('serverIP') || '';
  ctx.elements.useCustomIP.checked = localStorage.getItem('useCustomIP') === 'true';
  ctx.elements.metricsSource.value = localStorage.getItem('metricsSource') || 'cadvisor';
  localStorage.removeItem('heroOverviewHidden');

  const savedInterval = localStorage.getItem('refreshInterval');
  ctx.state.refreshIntervalMs = savedInterval ? parseInt(savedInterval, 10) : parseInt(ctx.elements.refreshInterval.value, 10);
  ctx.elements.refreshInterval.value = String(ctx.state.refreshIntervalMs);

  const savedChartType = localStorage.getItem('chartType');
  if (savedChartType) {
    ctx.state.currentChartType = savedChartType;
    const radio = document.getElementById(`${savedChartType}ChartBtn`);
    if (radio) {
      radio.checked = true;
    }
  }

  ctx.elements.columnToggleInputs.forEach((input) => {
    const saved = localStorage.getItem(`colVisible-${input.value}`) ?? localStorage.getItem(input.id);
    const defaultChecked = !['netio', 'blockio', 'image', 'ports', 'restarts', 'ui', 'update'].includes(input.value);
    if (input.value === 'name') {
      input.checked = true;
      input.disabled = true;
    } else {
      input.checked = saved ? saved === 'true' : defaultChecked;
    }
    ctx.elements.metricsTable.classList.toggle(`hide-col-${input.value}`, !input.checked);
  });
}

function initDashboardViewTabs() {
  const tabs = [ctx.elements.dashboardContainersTab, ctx.elements.dashboardComposeTab].filter(Boolean);
  if (tabs.length === 0) {
    return;
  }

  tabs.forEach((tab) => {
    tab.addEventListener('shown.bs.tab', (event) => {
      const viewName = event.target.dataset.dashboardView || 'containers';
      localStorage.setItem('dashboardView', viewName);
      if (viewName === 'containers' && ctx.state.usageChart) {
        requestAnimationFrame(() => ctx.state.usageChart.resize());
      }
    });
  });

  const isMobileLayout = window.matchMedia('(max-width: 767.98px)').matches;
  const savedView = isMobileLayout
    ? (document.body.dataset.mobileSection === 'stacks' ? 'compose' : 'containers')
    : (localStorage.getItem('dashboardView') || 'containers');
  const target = tabs.find((tab) => tab.dataset.dashboardView === savedView) || ctx.elements.dashboardContainersTab || tabs[0];
  if (target) {
    bootstrap.Tab.getOrCreateInstance(target).show();
  }
}

function bindControls() {
  ctx.elements.themeToggleButton.onclick = toggleTheme;
  ctx.elements.scrollTopButton.onclick = () => window.scrollTo({ top: 0, behavior: 'smooth' });
  ctx.elements.logoutBtn.onclick = logout;
  ctx.elements.resetFiltersBtn.addEventListener('click', resetFilters);
  ctx.elements.toggleRefreshBtn.addEventListener('click', () => {
    ctx.state.autoRefreshPaused = !ctx.state.autoRefreshPaused;
    if (!ctx.state.autoRefreshPaused) {
      fetchMetrics();
    }
    restartAutoRefresh();
  });
  ctx.elements.saveSettingsBtn?.addEventListener('click', saveSettings);
  document.getElementById('toggleColsBtn').addEventListener('click', toggleAllColumns);
  document.getElementById('checkUpdatesBtn').addEventListener('click', async () => {
    setStatusMessage(ctx, 'Checking for updates...', 'info');
    try {
      await fetch(`/api/metrics?${buildMetricsQuery({ force: true }).toString()}`);
      setStatusMessage(ctx, 'Update check completed.', 'success');
    } catch (error) {
      setStatusMessage(ctx, 'Error checking for updates.', 'danger');
    }
  });

  ctx.elements.quickFilterButtons.forEach((button) => {
    button.addEventListener('click', () => setQuickFilter(button.dataset.quickFilter));
  });

  [ctx.elements.filterStatus, ctx.elements.sortBy, ctx.elements.sortDir].forEach((element) => {
    element.addEventListener('change', () => {
      localStorage.setItem(element.id, element.value);
      fetchMetrics();
      restartAutoRefresh();
    });
  });

  ctx.elements.filterProject.addEventListener('change', () => {
    localStorage.setItem('filterProject', ctx.elements.filterProject.value);
    fetchMetrics();
    restartAutoRefresh();
  });

  ctx.elements.filterName.addEventListener('input', () => {
    localStorage.setItem('filterName', ctx.elements.filterName.value);
    clearTimeout(ctx.state.searchDebounceTimer);
    ctx.state.searchDebounceTimer = setTimeout(() => {
      fetchMetrics();
      restartAutoRefresh();
    }, 200);
  });

  ctx.elements.maxItems.addEventListener('change', () => {
    localStorage.setItem('maxItems', ctx.elements.maxItems.value);
    fetchMetrics();
    restartAutoRefresh();
  });

  ctx.elements.refreshInterval.addEventListener('change', () => {
    ctx.state.refreshIntervalMs = parseInt(ctx.elements.refreshInterval.value, 10);
    localStorage.setItem('refreshInterval', ctx.state.refreshIntervalMs);
    updateRefreshUi(ctx);
    fetchMetrics();
    restartAutoRefresh();
  });

  ctx.elements.metricsSource.addEventListener('change', () => {
    localStorage.setItem('metricsSource', ctx.elements.metricsSource.value);
    fetchMetrics();
    restartAutoRefresh();
  });

  ctx.elements.filterRange.addEventListener('change', () => {
    localStorage.setItem('filterRange', ctx.elements.filterRange.value);
    if (ctx.elements.historyChartModalEl?.classList.contains('show') && ctx.state.currentChartContainerId) {
      charts.fetchAndRenderChart();
    } else {
      fetchMetrics();
      restartAutoRefresh();
    }
  });
}

async function init() {
  patchFetchWithCsrf();
  loadPersistedControls();
  charts.init();
  logs.init();
  table.init();
  users.init();
  apiKeys.init();
  mobile.init();
  notifications.init();
  updates.init();
  await notifications.loadSettings();
  await initProjects();
  initDashboardViewTabs();
  initHeaderSorting();
  bindControls();
  updateQuickFilterUI(ctx);
  updateRefreshUi(ctx);
  notifications.fetchSystemStatus();
  await fetchMetrics();
  restartAutoRefresh();
}

document.addEventListener('DOMContentLoaded', () => {
  init().catch((error) => {
    console.error('Dashboard initialization failed:', error);
    setStatusMessage(ctx, 'Initialization error. Check console.', 'danger');
  });
});
