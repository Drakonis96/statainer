import { setStatusMessage } from './helpers.js';

export function createUserController(ctx, deps) {
  let hideSettingsModalTimer = null;
  let pendingSettingsModalOpen = false;
  let pendingSettingsModalFrame = null;

  function forceHideModal(modalElement) {
    if (!modalElement?.classList.contains('show')) {
      return;
    }

    modalElement.classList.remove('show');
    modalElement.style.display = 'none';
    modalElement.setAttribute('aria-hidden', 'true');
    modalElement.removeAttribute('aria-modal');
    document.body.classList.remove('modal-open');
    document.body.style.removeProperty('padding-right');
    document.querySelectorAll('.modal-backdrop').forEach((element) => element.remove());
  }

  function hideSettingsModal() {
    const modalElement = ctx.elements.settingsModalEl;
    if (!modalElement) {
      return;
    }

    const modal = bootstrap.Modal.getOrCreateInstance(modalElement);
    modal.hide();

    if (hideSettingsModalTimer) {
      window.clearTimeout(hideSettingsModalTimer);
    }

    hideSettingsModalTimer = window.setTimeout(() => {
      hideSettingsModalTimer = null;
      forceHideModal(modalElement);
    }, 250);
  }

  function cancelPendingSettingsModalOpen() {
    if (pendingSettingsModalFrame !== null) {
      window.cancelAnimationFrame(pendingSettingsModalFrame);
      pendingSettingsModalFrame = null;
    }
  }

  function flushPendingSettingsModalOpen() {
    const modalElement = ctx.elements.settingsModalEl;
    const modal = ctx.state.settingsModal;
    if (!pendingSettingsModalOpen || !modalElement || !modal) {
      cancelPendingSettingsModalOpen();
      return;
    }

    const transitionInProgress = Boolean(modal._isTransitioning) || window.getComputedStyle(modalElement).display !== 'none';
    if (transitionInProgress) {
      pendingSettingsModalFrame = window.requestAnimationFrame(flushPendingSettingsModalOpen);
      return;
    }

    pendingSettingsModalOpen = false;
    cancelPendingSettingsModalOpen();
    modal.show();
  }

  function updateUserInfoLabel(user) {
    if (!user || !user.username) {
      return;
    }
    ctx.elements.userInfoBtn.innerHTML = `<img src="/static/icons/header_user.svg" alt="User" width="18" height="18"> ${user.username} (${user.role})`;
    if (ctx.elements.sidebarUserLabel) {
      ctx.elements.sidebarUserLabel.textContent = `${user.username} (${user.role})`;
    }
  }

  async function fetchWhoAmI() {
    const response = await fetch('/whoami');
    const currentUser = await response.json();
    ctx.state.currentUser = currentUser;
    updateUserInfoLabel(currentUser);
    return currentUser;
  }

  async function handlePasswordSubmit(event) {
    event.preventDefault();
    const current = ctx.elements.currentPassword.value;
    const nextPassword = ctx.elements.newPassword.value;
    const confirmPassword = ctx.elements.confirmPassword.value;
    const errorDiv = ctx.elements.passwordError;
    errorDiv.style.display = 'none';
    errorDiv.textContent = '';

    if (!current || !nextPassword || !confirmPassword) {
      errorDiv.textContent = 'All fields are required.';
      errorDiv.style.display = 'block';
      return;
    }
    if (nextPassword !== confirmPassword) {
      errorDiv.textContent = 'New passwords do not match.';
      errorDiv.style.display = 'block';
      return;
    }

    const response = await fetch('/api/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ current_password: current, new_password: nextPassword }),
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) {
      errorDiv.textContent = payload.error || 'Error changing password.';
      errorDiv.style.display = 'block';
      return;
    }

    hideSettingsModal();
    setStatusMessage(ctx, 'Password changed successfully.', 'success');
    ctx.elements.passwordForm.reset();
  }

  function renderUserColumnsCheckboxes(selectedColumns = []) {
    const container = ctx.elements.userColumnsCheckboxes;
    container.innerHTML = '';
    deps.getAllTableColumns().forEach((column) => {
      const wrapper = document.createElement('div');
      wrapper.className = 'form-check form-check-inline';
      wrapper.innerHTML = `
        <input class="form-check-input" type="checkbox" value="${column.key}" id="userCol_${column.key}" ${selectedColumns.length === 0 || selectedColumns.includes(column.key) ? 'checked' : ''}>
        <label class="form-check-label" for="userCol_${column.key}">${column.label}</label>
      `;
      container.appendChild(wrapper);
    });
  }

  async function loadUsersList() {
    const usersList = ctx.elements.usersList;
    usersList.innerHTML = '<div class="text-muted">Loading users...</div>';

    try {
      const response = await fetch('/api/users');
      if (!response.ok) {
        throw new Error('Failed to fetch users');
      }
      const users = await response.json();
      usersList.innerHTML = '';

      const filteredUsers = users.filter((user) => user.role !== 'admin');
      if (filteredUsers.length === 0) {
        usersList.innerHTML = '<div class="text-muted">No users found.</div>';
        return;
      }

      filteredUsers.forEach((user) => {
        const wrapper = document.createElement('div');
        wrapper.className = 'mb-2 border rounded p-2';
        wrapper.innerHTML = `
          <div class="d-flex align-items-center justify-content-between">
            <div><strong>${user.username}</strong> <span class="badge bg-secondary">user</span></div>
            <div>
              <button class="btn btn-link btn-sm toggle-user-details" data-username="${user.username}">
                <span class="toggle-icon">[+]</span>
              </button>
              <button class="btn btn-danger btn-sm delete-user-btn" data-username="${user.username}">Delete</button>
            </div>
          </div>
          <div class="user-details mt-2" data-username="${user.username}" style="display:none;">
            <strong>Columns:</strong>
            <div class="user-cols-checkboxes" data-username="${user.username}"></div>
            <button class="btn btn-primary btn-sm mt-1 save-cols-btn" data-username="${user.username}">Save columns</button>
            <span class="save-cols-status ms-2"></span>
          </div>
        `;
        usersList.appendChild(wrapper);

        const columnsContainer = wrapper.querySelector('.user-cols-checkboxes');
        deps.getAllTableColumns().forEach((column) => {
          const item = document.createElement('div');
          item.className = 'form-check form-check-inline';
          item.innerHTML = `
            <input class="form-check-input" type="checkbox" value="${column.key}" id="userCol_${user.username}_${column.key}" ${user.columns.includes(column.key) ? 'checked' : ''}>
            <label class="form-check-label" for="userCol_${user.username}_${column.key}">${column.label}</label>
          `;
          columnsContainer.appendChild(item);
        });
      });

      usersList.querySelectorAll('.delete-user-btn').forEach((button) => {
        button.addEventListener('click', async () => {
          const username = button.dataset.username;
          const confirmed = await deps.confirmAction({
            title: 'Delete user',
            message: `Delete user '${username}'? This cannot be undone.`,
            confirmLabel: 'Delete user',
            cancelLabel: 'Cancel',
            tone: 'danger',
          });
          if (!confirmed) {
            return;
          }
          const response = await fetch(`/api/users/${encodeURIComponent(username)}`, { method: 'DELETE' });
          if (response.ok) {
            loadUsersList();
          } else {
            setStatusMessage(ctx, 'Error deleting user.', 'danger');
          }
        });
      });

      usersList.querySelectorAll('.toggle-user-details').forEach((button) => {
        button.addEventListener('click', () => {
          const username = button.dataset.username;
          const details = usersList.querySelector(`.user-details[data-username="${username}"]`);
          const toggleIcon = button.querySelector('.toggle-icon');
          const visible = details.style.display !== 'none';
          details.style.display = visible ? 'none' : 'block';
          toggleIcon.textContent = visible ? '[+]' : '[-]';
        });
      });

      usersList.querySelectorAll('.save-cols-btn').forEach((button) => {
        button.addEventListener('click', async () => {
          const username = button.dataset.username;
          const columnsContainer = usersList.querySelector(`.user-cols-checkboxes[data-username="${username}"]`);
          const selectedColumns = Array.from(columnsContainer.querySelectorAll('.form-check-input:checked')).map((checkbox) => checkbox.value);
          const status = button.parentElement.querySelector('.save-cols-status');
          status.textContent = 'Saving...';

          const response = await fetch(`/api/users/${encodeURIComponent(username)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ columns: selectedColumns }),
          });

          if (response.ok) {
            status.textContent = 'Saved!';
            status.style.color = 'green';
            setTimeout(() => {
              status.textContent = '';
            }, 1500);
          } else {
            status.textContent = 'Error';
            status.style.color = 'red';
          }
        });
      });
    } catch (error) {
      console.error('Error loading users:', error);
      usersList.innerHTML = '<div class="text-danger">Error loading users.</div>';
    }
  }

  async function handleCreateUser(event) {
    event.preventDefault();
    const username = ctx.elements.newUsername.value.trim();
    const password = ctx.elements.newUserPassword.value;
    const confirmPassword = ctx.elements.confirmUserPassword.value;
    const errorDiv = ctx.elements.userFormError;
    errorDiv.style.display = 'none';
    errorDiv.textContent = '';

    if (!username || !password || !confirmPassword) {
      errorDiv.textContent = 'All fields are required.';
      errorDiv.style.display = 'block';
      return;
    }
    if (password !== confirmPassword) {
      errorDiv.textContent = 'Passwords do not match.';
      errorDiv.style.display = 'block';
      return;
    }

    const selectedColumns = Array.from(ctx.elements.userColumnsCheckboxes.querySelectorAll('.form-check-input:checked')).map((checkbox) => checkbox.value);
    try {
      const response = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, columns: selectedColumns }),
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        errorDiv.textContent = payload.error || 'Error creating user.';
        errorDiv.style.display = 'block';
        return;
      }

      ctx.elements.createUserForm.reset();
      renderUserColumnsCheckboxes();
      errorDiv.style.display = 'block';
      errorDiv.style.color = 'green';
      errorDiv.textContent = 'User created.';
      setTimeout(() => {
        errorDiv.style.display = 'none';
        errorDiv.style.color = '';
      }, 2000);
      loadUsersList();
    } catch (error) {
      errorDiv.textContent = 'Network error.';
      errorDiv.style.display = 'block';
    }
  }

  async function blockAdminFeaturesIfUser() {
    const currentUser = ctx.state.currentUser || await fetchWhoAmI();
    if (!currentUser || currentUser.role === 'admin') {
      return;
    }

    const blockInteraction = (element, message) => {
      if (!element) return;
      element.classList.add('disabled');
      element.style.pointerEvents = 'auto';
      element.style.opacity = '0.5';
      element.title = message;
      element.addEventListener('click', (event) => {
        event.preventDefault();
        deps.showNotice({
          title: 'Admin access required',
          message,
          confirmLabel: 'Close',
          tone: 'warning',
        });
        if (ctx.elements.notifPanel) {
          ctx.elements.notifPanel.style.display = 'none';
        }
        return false;
      });
    };

    blockInteraction(document.getElementById('notifToggle'), 'Only admin has access to this feature');
    blockInteraction(document.getElementById('updateManagerToggle'), 'Only admin has access to this feature');
    blockInteraction(document.getElementById('sidebarUpdateManagerToggle'), 'Only admin has access to this feature');
    blockInteraction(ctx.elements.tabManageUser, 'Only admin has access to this feature');
    blockInteraction(ctx.elements.tabApiKeys, 'Only admin has access to this feature');
    if (ctx.elements.testNotifBtn) {
      ctx.elements.testNotifBtn.disabled = true;
      ctx.elements.testNotifBtn.title = 'Only admin can send notifications';
    }
  }

  function openSettings() {
    if (hideSettingsModalTimer) {
      window.clearTimeout(hideSettingsModalTimer);
      hideSettingsModalTimer = null;
    }

    const modalElement = ctx.elements.settingsModalEl;
    const modal = ctx.state.settingsModal;
    if (!modalElement || !modal) {
      return;
    }
    if (modalElement.classList.contains('show')) {
      return;
    }

    const transitionInProgress = Boolean(modal._isTransitioning) || window.getComputedStyle(modalElement).display !== 'none';
    if (transitionInProgress) {
      if (pendingSettingsModalOpen && pendingSettingsModalFrame !== null) {
        return;
      }
      pendingSettingsModalOpen = true;
      pendingSettingsModalFrame = window.requestAnimationFrame(flushPendingSettingsModalOpen);
      return;
    }

    pendingSettingsModalOpen = false;
    cancelPendingSettingsModalOpen();
    modal.show();
  }

  function init() {
    ctx.state.settingsModal = bootstrap.Modal.getOrCreateInstance(ctx.elements.settingsModalEl);
    ctx.elements.settingsBtn.addEventListener('click', openSettings);
    ctx.elements.passwordForm.addEventListener('submit', handlePasswordSubmit);
    ctx.elements.createUserForm?.addEventListener('submit', handleCreateUser);

    ctx.elements.tabManageUser?.addEventListener('shown.bs.tab', () => {
      renderUserColumnsCheckboxes();
      loadUsersList();
    });

    fetchWhoAmI().then(blockAdminFeaturesIfUser);
  }

  return {
    init,
    openSettings,
    fetchWhoAmI,
    updateUserInfoLabel,
    renderUserColumnsCheckboxes,
    loadUsersList,
  };
}
