"""Flask route for the LLM impact report (FlowTrace integration)."""
import json

from flask import jsonify, request

from flowtrace.capstone_impact import assess
from flowtrace.providers import get_provider

_provider = None


def _get_provider():
    """Connect to the model once and reuse the connection for every report."""
    global _provider
    if _provider is None:
        _provider = get_provider()
    return _provider


def register_impact_routes(app):
    @app.route("/api/impact-report", methods=["POST"])
    def impact_report():
        body = request.get_json(silent=True) or {}
        target = str(body.get("target", "")).strip()
        if not target:
            return jsonify({"error": "Send a target: a repository name or its target_pk."}), 400
        try:
            result = assess(target, provider=_get_provider(), force=bool(body.get("force")))
        except json.JSONDecodeError:
            return jsonify({"error": "The model did not return valid JSON. Try again."}), 502
        except ValueError as err:          # repository not found
            return jsonify({"error": str(err)}), 404
        except RuntimeError as err:        # missing API key
            return jsonify({"error": str(err)}), 503
        except Exception as err:
            app.logger.exception("Impact report failed")
            return jsonify({"error": f"Impact report failed: {err}"}), 500
        return jsonify(result)