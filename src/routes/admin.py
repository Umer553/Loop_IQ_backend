from fastapi import APIRouter, Request, Depends, HTTPException

router = APIRouter(prefix="/admin", tags=["Admin"])

def require_role(role: str):
    def _dep(request: Request):
        u = getattr(request.state, "user", None)
        if not u:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if u.role != role:
            raise HTTPException(status_code=403, detail="Forbidden: insufficient role")
        return u
    return _dep

@router.get("/dashboard")
def admin_dashboard(user=Depends(require_role("admin"))):
    return {"message": f"Welcome Admin {user.email}"}
