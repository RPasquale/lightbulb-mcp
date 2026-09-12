"""Runnable Auth0 customer application. Install lightbulb-mcp[saas-kit]."""
from __future__ import annotations

import argparse
import html
import json
import os
import secrets
from pathlib import Path
from urllib.parse import quote, urlsplit

from lightbulb.company_customer_self_service import CustomerSelfService, CustomerSelfServiceError
from lightbulb.company_saas_kit import CustomerInvitationDelivery, CustomerSaasIdentityStore, CustomerSaasKit


def create_customer_saas_app(kit: CustomerSaasKit, store: CustomerSaasIdentityStore, service: CustomerSelfService,
                             *, session_secret: str, auth0_client_secret: str):
    from authlib.integrations.starlette_client import OAuth
    from starlette.applications import Starlette
    from starlette.exceptions import HTTPException
    from starlette.middleware import Middleware
    from starlette.middleware.sessions import SessionMiddleware
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
    from starlette.routing import Route
    from starlette.concurrency import run_in_threadpool

    if len(session_secret) < 32 or not auth0_client_secret:
        raise ValueError("strong server secrets required")
    oauth = OAuth()
    oauth.register("auth0", client_id=kit.auth0_client_id, client_secret=auth0_client_secret,
                   server_metadata_url=f"{kit.auth0_issuer}/.well-known/openid-configuration",
                   client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"})

    def identity(request):
        value = request.session.get("identity")
        if not isinstance(value, dict) or not value.get("sub") or not value.get("email"):
            raise HTTPException(401, "Sign in to continue")
        return value

    async def body(request):
        if request.headers.get("origin") != kit.public_origin or int(request.headers.get("content-length", "0")) > 4096:
            raise HTTPException(403, "Request origin rejected")
        raw = await request.body()
        if len(raw) > 4096:
            raise HTTPException(413)
        if request.headers.get("content-type", "").split(";")[0] == "application/json":
            data = json.loads(raw)
        else:
            from urllib.parse import parse_qs
            data = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
        if not isinstance(data, dict) or not secrets.compare_digest(str(data.get("csrf", "")), request.session.get("csrf", "invalid")):
            raise HTTPException(403, "Request confirmation expired")
        return data

    async def login(request):
        return await oauth.auth0.authorize_redirect(request, f"{kit.public_origin}/auth/callback")

    async def callback(request):
        try:
            token = await oauth.auth0.authorize_access_token(request)
            # Authlib verifies issuer, signature, audience, expiry, nonce and OAuth state.
            info = token.get("userinfo", {})
            if not token.get("id_token") or info.get("iss") != kit.auth0_issuer + "/" or info.get("email_verified") is not True or not isinstance(info.get("sub"), str) or not 1 <= len(info["sub"]) <= 200 or not isinstance(info.get("email"), str):
                raise ValueError("verified identity required")
            invitation = request.session.get("invitation")
            request.session.clear()
            request.session.update(identity={"sub": info["sub"], "email": info["email"].lower()}, csrf=secrets.token_urlsafe(32))
            if invitation:
                await run_in_threadpool(store.accept, invitation, info["email"].lower(), info["sub"])
                return RedirectResponse(f"/workspaces/{quote(invitation, safe='')}", status_code=303)
            return RedirectResponse("/", status_code=303)
        except Exception:
            request.session.clear()
            raise HTTPException(401, "Verified sign-in failed")

    async def invite(request):
        workspace = request.path_params["workspace"]
        # This is only a routing hint; email-verified identity and the stored invitation authorize acceptance.
        if len(workspace) > 160:
            raise HTTPException(404)
        request.session["invitation"] = workspace
        return RedirectResponse("/login", status_code=303)

    async def home(request):
        if not request.session.get("identity"):
            return HTMLResponse('<h1>Welcome</h1><a href="/login">Sign in</a>')
        who = identity(request)
        accessible = []
        for binding in kit.bindings:
            try:
                context = await run_in_threadpool(store.context, binding.workspace_ref, who["sub"])
                if context.get("member_status") == "active":
                    accessible.append(f'<li><a href="/workspaces/{quote(binding.workspace_ref, safe="")}">{html.escape(binding.workspace_ref)}</a></li>')
            except Exception:
                continue
        return HTMLResponse("<h1>Your workspaces</h1><ul>" + "".join(accessible) + "</ul>")

    async def workspace(request):
        who, name = identity(request), request.path_params["workspace"]
        try:
            context = await run_in_threadpool(store.context, name, who["sub"])
        except Exception:
            raise HTTPException(403, "Workspace unavailable")
        csrf = html.escape(request.session["csrf"], quote=True)
        forms = ""
        if context.get("can_manage"):
            for action, label in (("overview", "Billing and invoices"), ("plan", "Change plan"), ("cancel", "Cancel subscription"), ("payment_method", "Update payment method"), ("reconcile_access", "Apply confirmed billing changes"), ("invite", "Invite teammate"), ("remove_member", "Remove teammate or invitation")):
                field = '<input type="email" name="email" required placeholder="Teammate email">' if action in {"invite","remove_member"} else ""
                forms += f'<form method="post" action="/workspaces/{quote(name, safe="")}/actions"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="{action}">{field}<button>{label}</button></form>'
        if context.get("can_manage"):
            forms += f'<p><a href="/workspaces/{quote(name, safe="")}/actions">Request history</a></p>'
        return HTMLResponse(f'<h1>{html.escape(name)}</h1><p>Plan: {html.escape(context["plan_ref"])} · {context["member_count"]} of {context["seat_limit"]} seats · {html.escape(context["status"])}</p>{forms}')

    async def prepare(request):
        who, data = identity(request), await body(request)
        await owner(request,who)
        workspace = request.path_params["workspace"]
        action = await run_in_threadpool(service.prepare, workspace, who["sub"], data.get("action"), email=data.get("email"))
        if action["phase"] == "completed":
            return action_response(request, action)
        result = await run_in_threadpool(service.advance, workspace, who["sub"], action["action_ref"])
        return action_response(request, result)

    def action_response(request, result):
        if result.get("url"):
            return RedirectResponse(result["url"], status_code=303, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
        workspace = quote(request.path_params["workspace"], safe="")
        csrf = html.escape(request.session["csrf"], quote=True)
        labels = {"pending_approval": "Waiting for the business owner to approve this request.", "completed": "Your request completed.", "unknown": "This request needs business review before another attempt.", "review_required": "Billing or workspace details changed. Prepare a new request for review."}
        form = f'<form method="post" action="/workspaces/{workspace}/actions/{result["action_ref"]}"><input type="hidden" name="csrf" value="{csrf}"><button>Check request</button></form>' if result["phase"] in {"prepared", "pending_approval", "unknown"} else ""
        return HTMLResponse(f'<p>{labels.get(result["phase"], "Request prepared.")}</p>{form}', headers={"Cache-Control": "no-store"})

    async def advance(request):
        who = identity(request)
        await body(request)
        await owner(request,who)
        args = (request.path_params["workspace"], who["sub"], request.path_params["action_ref"])
        current = await run_in_threadpool(service.inspect_action, *args)
        operation = service.recover_action if current["phase"] == "unknown" else service.advance
        result = await run_in_threadpool(operation, *args)
        return action_response(request, result)

    async def history(request):
        who = identity(request)
        await owner(request, who)
        workspace = request.path_params["workspace"]
        try:
            page = await run_in_threadpool(service.history, workspace, who["sub"],
                                          after=request.query_params.get("after"))
        except ValueError:
            raise HTTPException(400, "Invalid history cursor")
        rows = "".join(f'<li><a href="/workspaces/{quote(workspace, safe="")}/actions/{row["action_ref"]}">{html.escape(row["action"] or "Request")}</a>: {html.escape(row["phase"].replace("_", " "))}</li>' for row in page["actions"])
        more = f'<a href="?after={page["next_cursor"]}">More requests</a>' if page["next_cursor"] else ""
        return HTMLResponse(f"<h1>Request history</h1><ul>{rows}</ul>{more}", headers={"Cache-Control": "no-store"})

    async def inspect(request):
        who = identity(request)
        await owner(request, who)
        try:
            result = await run_in_threadpool(service.inspect_action, request.path_params["workspace"],
                                            who["sub"], request.path_params["action_ref"])
        except Exception:
            raise HTTPException(404, "Request unavailable")
        return action_response(request, result)

    async def billing(request):
        who = identity(request)
        await owner(request,who)
        result = await run_in_threadpool(service.reconcile_subscription, request.path_params["workspace"], who["sub"])
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    async def owner(request,who):
        try:
            context=await run_in_threadpool(store.context,request.path_params["workspace"],who["sub"])
            if context.get("can_manage") is not True:
                raise ValueError("owner required")
        except Exception:
            raise HTTPException(403,"Workspace owner access required")

    async def customer_error(request,exception):
        return HTMLResponse("<p>This request requires business review or updated customer details.</p>",status_code=409)

    async def feature(request):
        who = identity(request)
        access = await run_in_threadpool(store.authorize, request.path_params["workspace"], who["sub"])
        if access.get("access_active") is not True or request.path_params["feature"] not in access.get("features", []):
            raise HTTPException(403, "Your current plan does not allow this feature")
        return JSONResponse({"available": True, "feature": request.path_params["feature"]}, headers={"Cache-Control": "no-store"})

    async def logout(request):
        await body(request)
        request.session.clear()
        return RedirectResponse("/", status_code=303)

    app = Starlette(routes=[Route("/", home), Route("/login", login), Route("/auth/callback", callback),
        Route("/invite/{workspace}", invite), Route("/logout", logout, methods=["POST"]),
        Route("/workspaces/{workspace}", workspace), Route("/workspaces/{workspace}/actions", prepare, methods=["POST"]),
        Route("/workspaces/{workspace}/actions", history, methods=["GET"]),
        Route("/workspaces/{workspace}/actions/{action_ref}", inspect, methods=["GET"]),
        Route("/workspaces/{workspace}/actions/{action_ref}", advance, methods=["POST"]),
        Route("/workspaces/{workspace}/billing", billing), Route("/workspaces/{workspace}/features/{feature}", feature)],
        exception_handlers={CustomerSelfServiceError:customer_error},
        middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=[urlsplit(kit.public_origin).hostname]),
                    Middleware(SessionMiddleware, secret_key=session_secret, session_cookie="customer_session", https_only=True, same_site="lax", max_age=3600)])
    return app


def main():
    parser = argparse.ArgumentParser(description="Run the customer SaaS integration kit")
    parser.add_argument("command", choices=("serve", "check", "deliver-invitations", "schema"))
    parser.add_argument("--config", type=Path)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--after-workspace", default="")
    parser.add_argument("--after-email", default="")
    args = parser.parse_args()
    if args.command == "schema":
        print(CustomerSaasKit.application_schema() + "\n" + CustomerSaasKit.integration_schema())
        return
    if args.config is None:
        parser.error("--config required")
    kit = CustomerSaasKit.model_validate_json(args.config.read_text())
    import psycopg
    from lightbulb.auth import JwtAuth
    from lightbulb.client import LightbulbClient
    client = LightbulbClient(os.environ["LIGHTBULB_BASE_URL"], JwtAuth(os.environ["LIGHTBULB_JWT"], os.environ["LIGHTBULB_TENANT_ID"], os.environ["LIGHTBULB_COMPANY_ID"]))
    store = CustomerSaasIdentityStore(kit.application_id, lambda: psycopg.connect(os.environ["CUSTOMER_IDENTITY_DATABASE_URL"]))
    service = CustomerSelfService(kit, store, client)
    if args.command == "check":
        import httpx
        report=service.check_setup()
        metadata=httpx.get(f"{kit.auth0_issuer}/.well-known/openid-configuration",timeout=20,follow_redirects=False)
        metadata.raise_for_status()
        discovery=metadata.json()
        report["identity_discovery_verified"]=discovery.get("issuer")==kit.auth0_issuer+"/" and all(urlsplit(discovery.get(k, "")).scheme=="https" for k in ("authorization_endpoint","token_endpoint","jwks_uri"))
        report["price_policies_complete"]=all({p.price_id for p in b.price_policies}==set(b.allowed_price_ids) for b in kit.bindings)
        print(json.dumps(report, indent=2))
        if not report["destination"].get("ready") or not report["identity_discovery_verified"] or not report["price_policies_complete"]:
            raise SystemExit(1)
    elif args.command == "deliver-invitations":
        delivery = CustomerInvitationDelivery(kit, store, CustomerInvitationDelivery.smtp_sender(os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", "465")), os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"]), os.environ["SMTP_FROM"])
        rows=store.pending(args.after_workspace,args.after_email)
        outcomes = [delivery.deliver(row) for row in rows]
        print(json.dumps({"processed": len(outcomes), "sent": outcomes.count("sent"), "unknown": outcomes.count("unknown"),
                          "next_cursor": {k:rows[-1][k] for k in ("workspace_ref","email")} if len(rows)==100 else None}))
    else:
        import uvicorn
        app = create_customer_saas_app(kit, store, service, session_secret=os.environ["CUSTOMER_SESSION_SECRET"], auth0_client_secret=os.environ["AUTH0_CLIENT_SECRET"])
        uvicorn.run(app, host="127.0.0.1", port=args.port, proxy_headers=False)


if __name__ == "__main__":
    main()
