"""Flask routes for Phase 2: suggesting data dependencies from code (FlowTrace)."""
import json

from flask import jsonify, request

from flowtrace import suggestion_store
from flowtrace.capstone_discovery import discover
from impact_routes import _get_provider


def register_discovery_routes(app):
    @app.route("/api/discovery/run", methods=["POST"])
    def discovery_run():
        """Read one target's code and save its suggestions. Body: {"target": pk or name}"""
        body = request.get_json(silent=True) or {}
        target = str(body.get("target", "")).strip()
        if not target:
            return jsonify({"error": "Send a target: a repository name or its target_pk."}), 400
        try:
            result = discover(target, provider=_get_provider(), save=True)
        except json.JSONDecodeError:
            return jsonify({"error": "The model did not return valid JSON. Try again."}), 502
        except ValueError as err:          # not found, not a local folder, or too large
            return jsonify({"error": str(err)}), 400
        except RuntimeError as err:        # missing API key
            return jsonify({"error": str(err)}), 503
        except Exception as err:
            app.logger.exception("Discovery failed")
            return jsonify({"error": f"Discovery failed: {err}"}), 500
        return jsonify(result)

    @app.route("/api/discovery/evidence", methods=["GET"])
    def discovery_evidence():
        """Code evidence behind every approved, still-recorded link."""
        return jsonify({"rows": suggestion_store.approved_evidence()})
    @app.route("/api/discovery/suggestions", methods=["GET"])
    def discovery_list():
        """List suggestions. ?status=pending (default), approved or rejected"""
        status = request.args.get("status", "pending")
        if status not in ("pending", "approved", "rejected"):
            return jsonify({"error": "status must be pending, approved or rejected."}), 400
        return jsonify({"rows": suggestion_store.list_suggestions(status)})

    @app.route("/api/discovery/suggestions/<int:suggestion_id>/<action>", methods=["POST"])
    def discovery_decide(suggestion_id, action):
        """Approve (creates the data dependency) or reject one suggestion."""
        if action not in ("approve", "reject"):
            return jsonify({"error": "Use /approve or /reject."}), 404
        try:
            status = suggestion_store.decide(suggestion_id, action == "approve")
        except LookupError as err:
            return jsonify({"error": str(err)}), 404
        except ValueError as err:          # already approved or rejected
            return jsonify({"error": str(err)}), 409
        return jsonify({"suggestion_id": suggestion_id, "status": status})
