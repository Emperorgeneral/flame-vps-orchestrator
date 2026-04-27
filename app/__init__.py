"""flame-vps-orchestrator package.

Standalone service that runs on the dedicated Terminal VPS. It receives
HMAC-signed RPCs from the FlameBot backend (see flame-backend/vps_routes.py
``_orchestrator_call``) and drives MT4/MT5 terminal lifecycles + EA attach.

Phase 2: skeleton only. Provisioner / EA-deployer hooks are stubs so the
end-to-end contract (backend -> orchestrator -> webhook -> backend) can be
exercised without spawning real MT terminals yet.
"""

__version__ = "0.1.0"
