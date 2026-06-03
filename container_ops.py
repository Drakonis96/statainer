# -*- coding: utf-8 -*-
"""Shared container lifecycle operations.

These helpers are consumed by the external API blueprint (``api_routes``) so it
can start/stop/restart/update containers without duplicating Docker plumbing.
The session-based UI route keeps its own inline logic for backwards
compatibility with existing tests.
"""

import docker

import update_manager
from docker_client import get_docker_client

errors = docker.errors

VALID_ACTIONS = ('start', 'stop', 'restart', 'update')


def execute_container_action(action, container_id, actor_username=None):
    """Run a container action and return a normalized result dict.

    Result keys:
      ok           -> bool
      status_code  -> suggested HTTP status code
      action       -> the normalized action
      container_id -> the resolved container id (if found)
      name         -> container name (if found)
      message      -> human readable message
      error        -> machine readable error code (on failure)
      history_entry-> update history entry (update action only)
    """
    normalized = (action or '').strip().lower()
    if normalized not in VALID_ACTIONS:
        return {
            'ok': False,
            'status_code': 400,
            'action': normalized,
            'error': 'invalid_action',
            'message': f"Invalid action '{normalized}'.",
        }

    try:
        client = get_docker_client()
        container = client.containers.get(container_id)
        name = str(container.name)
        resolved_id = getattr(container, 'id', container_id) or container_id

        if normalized == 'start':
            container.start()
            return _ok(normalized, resolved_id, name, f'Container {name} started.')
        if normalized == 'stop':
            container.stop()
            return _ok(normalized, resolved_id, name, f'Container {name} stopped.')
        if normalized == 'restart':
            container.restart()
            return _ok(normalized, resolved_id, name, f'Container {name} restarted.')

        # update
        result = update_manager.update_container_target(resolved_id, actor_username=actor_username)
        ok = bool(result.get('ok'))
        message = result.get('message') or (
            f'Container {name} updated successfully.' if ok else f'Container {name} update failed.'
        )
        return {
            'ok': ok,
            'status_code': 200 if ok else 409,
            'action': normalized,
            'container_id': resolved_id,
            'name': name,
            'message': message,
            'history_entry': result.get('history_entry'),
        }
    except errors.NotFound:
        return {
            'ok': False,
            'status_code': 404,
            'action': normalized,
            'container_id': container_id,
            'error': 'not_found',
            'message': f'Container {container_id} not found.',
        }
    except errors.DockerException as exc:
        return {
            'ok': False,
            'status_code': 502,
            'action': normalized,
            'container_id': container_id,
            'error': 'docker_error',
            'message': str(exc),
        }
    except Exception as exc:  # noqa: BLE001 - surface a generic error to callers
        return {
            'ok': False,
            'status_code': 500,
            'action': normalized,
            'container_id': container_id,
            'error': 'internal_error',
            'message': str(exc),
        }


def _ok(action, container_id, name, message):
    return {
        'ok': True,
        'status_code': 200,
        'action': action,
        'container_id': container_id,
        'name': name,
        'message': message,
    }
