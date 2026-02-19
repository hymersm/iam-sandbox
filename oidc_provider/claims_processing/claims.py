# async def claims_for_target(sub: str, scope: str, target: str, client: dict) -> dict:
#     scope_set = scopes_set(scope)

#     # 1) Expand scopes -> claim list for this target
#     claim_names = set()
#     async for sdef in col_scopes.find({"scope": {"$in": list(scope_set)}, "enabled": True}):
#         if target in sdef.get("targets", []):
#             claim_names.update(sdef.get("include_claims", []))

#     # Always include sub for OIDC-ish things
#     claim_names.add("sub")

#     # 2) Client policy gating (optional)
#     allowed_claims = set(client.get("allowed_claims", [])) or None
#     if allowed_claims is not None:
#         claim_names = {c for c in claim_names if c in allowed_claims or c == "sub"}

#     # 3) Load user
#     user = await col_users.find_one({"sub": sub})
#     if not user:
#         raise HTTPException(401, "unknown_sub")

#     # 4) Resolve claims
#     out = {"sub": sub}
#     defs = col_claims.find({"claim": {"$in": list(claim_names)}})
#     async for cdef in defs:
#         claim = cdef["claim"]
#         val = resolve_source(user, cdef.get("source"), default=cdef.get("default"))
#         out[claim] = val

#     return out
