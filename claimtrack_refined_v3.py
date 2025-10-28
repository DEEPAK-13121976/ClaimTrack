# claimtrack_refined_v3.py
# ClaimTrack v3 — Update: remove bill number from submission; Admin user soft-delete (anonymize)
import os
import random
import string
import time
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, Boolean, create_engine, ForeignKey, func
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------
# Config
# -----------------------
DEFAULT_SQLITE = "sqlite:///data/claims_refined_v3.db"
DB_URL = os.environ.get("DATABASE_URL", DEFAULT_SQLITE)
os.makedirs("data", exist_ok=True)

engine = create_engine(DB_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

WORKFLOW_CHAIN = ["Diarist", "Auditor", "AAO", "SAO", "Director", "DDO"]

# -----------------------
# Models
# -----------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, index=True, unique=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=True)  # comma-separated roles
    location = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    official_id = Column(String, nullable=True)
    is_admin = Column(Boolean, default=False)
    active = Column(Boolean, default=True)


class Claim(Base):
    __tablename__ = "claims"
    id = Column(Integer, primary_key=True)
    uid = Column(String, unique=True, index=True)
    submitter_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    submitter = relationship("User", foreign_keys=[submitter_id])
    location = Column(String, nullable=True)
    bill_no = Column(String, nullable=True)   # kept for backward compatibility but not populated by new UI
    claim_type = Column(String, nullable=False)
    amount = Column(Float, nullable=True)
    date_of_bill = Column(String, nullable=True)
    remarks = Column(Text, nullable=True)
    created_at = Column(DateTime, default=func.now())
    status = Column(String, default="pending")
    current_stage = Column(String, default="Diarist")
    archived = Column(Boolean, default=False)
    deleted_by = Column(String, nullable=True)
    deleted_remarks = Column(Text, nullable=True)
    deleted_at = Column(DateTime, nullable=True)
    payment_confirmed_at = Column(DateTime, nullable=True)


class WorkflowLog(Base):
    __tablename__ = "workflow_logs"
    id = Column(Integer, primary_key=True)
    claim_id = Column(Integer, ForeignKey("claims.id"))
    claim = relationship("Claim", foreign_keys=[claim_id])
    stage = Column(String)
    action = Column(String)
    remarks = Column(Text)
    acted_by = Column(Integer, ForeignKey("users.id"))
    timestamp = Column(DateTime, default=func.now())


Base.metadata.create_all(engine)

# -----------------------
# Helpers
# -----------------------
def get_db():
    return SessionLocal()


def make_uid():
    today = datetime.now().strftime("%Y%m%d")
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=5))
    return f"CT-{today}-{suffix}"


def seed_admin():
    db = get_db()
    if not db.query(User).filter(User.email == "admin@org.in").first():
        u = User(
            name="Admin",
            email="admin@org.in",
            password_hash=generate_password_hash("admin123"),
            role="Admin",
            is_admin=True,
            location="New Delhi",
        )
        db.add(u)
        db.commit()
    db.close()


seed_admin()


def has_role(user_roles, want):
    if not user_roles:
        return False
    roles_list = [r.strip() for r in user_roles.split(",") if r.strip()]
    return want in roles_list or "Admin" in roles_list


def get_next_role(role):
    try:
        idx = WORKFLOW_CHAIN.index(role)
        return WORKFLOW_CHAIN[idx + 1] if idx + 1 < len(WORKFLOW_CHAIN) else None
    except ValueError:
        return None


def get_prev_role(role):
    try:
        idx = WORKFLOW_CHAIN.index(role)
        return WORKFLOW_CHAIN[idx - 1] if idx - 1 >= 0 else None
    except ValueError:
        return None


def get_higher_roles(role):
    if role not in WORKFLOW_CHAIN:
        return []
    idx = WORKFLOW_CHAIN.index(role)
    return WORKFLOW_CHAIN[idx + 1:]


def get_lower_roles(role):
    if role not in WORKFLOW_CHAIN:
        return ["Claimant"]
    idx = WORKFLOW_CHAIN.index(role)
    return WORKFLOW_CHAIN[:idx] + ["Claimant"]


# -----------------------
# Streamlit UI & Auth
# -----------------------
st.set_page_config(page_title="ClaimTrack v3", layout="wide")
st.title("ClaimTrack — Refined v3")

if "user" not in st.session_state:
    st.session_state["user"] = None
if "landing" not in st.session_state:
    st.session_state["landing"] = None
if "rerun" not in st.session_state:
    st.session_state["rerun"] = False

# Login & Signup
def show_signup():
    st.subheader("Claimant Sign Up")
    with st.form("signup"):
        name = st.text_input("Full name")
        email = st.text_input("Official email")
        password = st.text_input("Password", type="password")
        location = st.selectbox("Office Location", ["New Delhi", "Mumbai", "Kolkata", "Chennai", "Bangalore"])
        official_id = st.text_input("Official ID (optional)")
        submitted = st.form_submit_button("Sign Up")
        if submitted:
            db = get_db()
            if db.query(User).filter(User.email == email, User.active == True).first():
                st.error("Email exists. Please login or contact admin to assign approver roles.")
                db.close()
                return
            u = User(
                name=name,
                email=email,
                password_hash=generate_password_hash(password),
                role="Claimant",
                location=location,
                official_id=official_id,
            )
            db.add(u)
            db.commit()
            db.close()
            st.success("Account created. Please log in.")


def show_login():
    st.subheader("Login")
    with st.form("login"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            db = get_db()
            user = db.query(User).filter(User.email == email, User.active == True).first()
            if user and check_password_hash(user.password_hash, password):
                st.session_state["user"] = {
                    "id": user.id,
                    "email": user.email,
                    "name": user.name,
                    "role": user.role or "",
                    "location": user.location,
                    "is_admin": user.is_admin,
                }
                # Intelligent landing routing
                if has_role(user.role or "", "DG"):
                    st.session_state["landing"] = "Dashboard"
                elif any(r in (user.role or "") for r in WORKFLOW_CHAIN):
                    st.session_state["landing"] = "Pending With Me"
                else:
                    st.session_state["landing"] = "My Claims"
                st.session_state["rerun"] = not st.session_state["rerun"]
                st.success("✅ Login successful! Redirecting...")
                time.sleep(1)
                st.rerun()
                db.close()
            else:
                st.error("Invalid credentials")
                db.close()


if st.session_state["user"] is None:
    col1, col2 = st.columns(2)
    with col1:
        show_login()
    with col2:
        show_signup()
    st.stop()

# Refresh user info
def refresh_user():
    db = get_db()
    u = db.query(User).filter(User.id == st.session_state["user"]["id"]).first()
    if u:
        st.session_state["user"].update(
            {"role": u.role or "", "name": u.name, "location": u.location, "is_admin": u.is_admin}
        )
    db.close()


refresh_user()

db = get_db()
current_user = db.query(User).get(st.session_state["user"]["id"])

# Sidebar menu with role restrictions: Dashboard only for Director/DG; Admin only for admins
menu = ["Submit Claim", "My Claims", "Pending With Me", "Processed Items"]
if has_role(current_user.role, "Director") or has_role(current_user.role, "DG"):
    menu.append("Dashboard")
if current_user.is_admin:
    menu.append("Admin")

# default selection uses landing
default_choice = st.session_state.get("landing") or menu[0]
choice = st.sidebar.selectbox("Menu", menu, index=menu.index(default_choice) if default_choice in menu else 0)
st.sidebar.write(f"Logged in: {current_user.name} ({current_user.email})")
st.sidebar.write(f"Role(s): {current_user.role or 'Claimant'}")
st.sidebar.write(f"Location: {current_user.location or 'N/A'}")
if st.sidebar.button("Logout"):
    st.session_state.clear()
    st.success("✅ Successfully logged out! Redirecting to login page...")
    time.sleep(1.5)
    st.rerun()

# -----------------------
# Admin
# -----------------------
if choice == "Admin":
    if not current_user.is_admin:
        st.error("Admin only")
        st.stop()
    st.header("Admin — User management")
    with st.form("create_official"):
        name = st.text_input("Name")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        location = st.selectbox("Location", ["New Delhi", "Mumbai", "Kolkata", "Chennai", "Bangalore"])
        role = st.selectbox("Role to assign", ["Diarist", "Auditor", "AAO", "SAO", "Director", "DDO", "Claimant"])
        phone = st.text_input("Phone")
        submitted = st.form_submit_button("Create Official")
        if submitted:
            if not email or not password:
                st.error("Email and password required")
            else:
                existing = db.query(User).filter(User.email == email).first()
                if existing:
                    roles = (existing.role or "")
                    role_list = [r.strip() for r in roles.split(",") if r.strip()]
                    if role not in role_list:
                        role_list.append(role)
                        existing.role = ",".join(role_list)
                        existing.name = name or existing.name
                        existing.location = location or existing.location
                        existing.phone = phone or existing.phone
                        db.commit()
                        st.success(f"Added role {role} to existing user {email}")
                    else:
                        st.info("User already has that role")
                else:
                    u = User(
                        name=name or email.split("@")[0],
                        email=email,
                        password_hash=generate_password_hash(password),
                        role=role,
                        location=location,
                        phone=phone,
                    )
                    db.add(u)
                    db.commit()
                    st.success("Official created")
    st.markdown("---")
    st.subheader("Existing users")
    users_df = pd.read_sql(db.query(User).statement, db.bind)
    st.dataframe(users_df[["id", "name", "email", "role", "location", "is_admin"]])

    # Admin password reset (Option A: all users)
    st.markdown("---")
    st.subheader("🔐 Reset User Password (Admin)")
    user_email = st.text_input("Enter user's email to reset", key="admin_reset_email")
    new_pwd = st.text_input("Enter new password", type="password", key="admin_reset_pwd")
    if st.button("Reset Password (Admin)"):
        if user_email and new_pwd:
            target = db.query(User).filter(User.email == user_email, User.active == True).first()
            if target:
                target.password_hash = generate_password_hash(new_pwd)
                db.commit()
                st.success(f"Password for {user_email} has been reset successfully.")
            else:
                st.error("User not found or inactive")
        else:
            st.warning("Please provide both email and new password.")

    st.markdown("---")
    st.subheader("🗑️ Delete (Deactivate) a user")
    # list non-admin active users except current admin
    candidates = db.query(User).filter(User.active == True).all()
    candidate_options = []
    for u in candidates:
        if u.id == current_user.id:
            continue
        if u.is_admin:
            continue
        candidate_options.append((u.id, f"{u.name} ({u.email})"))
    if not candidate_options:
        st.info("No deletable users available (cannot delete admins or yourself).")
    else:
        sel = st.selectbox("Select user to delete (admin only)", [opt[1] for opt in candidate_options], key="del_sel")
        if st.button("Delete User (Admin)"):
            # find selected id
            sel_id = None
            for tup in candidate_options:
                if tup[1] == sel:
                    sel_id = tup[0]
                    break
            if sel_id:
                target = db.query(User).get(sel_id)
                if target:
                    # soft-delete: anonymize and deactivate, keep claims for audit
                    target.active = False
                    target.name = "Deleted user"
                    target.email = f"deleted_{target.id}@disabled.local"
                    target.role = ""
                    db.commit()
                    # optionally log a workflow note for claims by this user
                    db.add(
                        WorkflowLog(
                            claim_id=None,
                            stage="System",
                            action="UserDeleted",
                            remarks=f"User {sel} deactivated by {current_user.email}",
                            acted_by=current_user.id,
                        )
                    )
                    db.commit()
                    st.success("User deactivated and anonymized. Their claims are retained for audit.")
                else:
                    st.error("Selected user not found")
    db.close()
    st.stop()

# -----------------------
# Submit Claim (removed bill number/reference)
# -----------------------
if choice == "Submit Claim":
    st.header("Submit New Claim")
    with st.form("submit"):
        claim_type = st.selectbox("Claim Type", ["Medical", "Travel", "LTC", "Office Advance", "Other"])
        amount = st.number_input("Amount", min_value=0.0, value=0.0, format="%.2f")
        date_of_bill = st.date_input("Bill Date")
        location = st.selectbox(
            "Office Location",
            ["New Delhi", "Mumbai", "Kolkata", "Chennai", "Bangalore"],
            index=["New Delhi", "Mumbai", "Kolkata", "Chennai", "Bangalore"].index(current_user.location)
            if current_user.location in ["New Delhi", "Mumbai", "Kolkata", "Chennai", "Bangalore"]
            else 0,
        )
        remarks = st.text_area("Remarks (optional, up to 100 words)", max_chars=800)
        submitted = st.form_submit_button("Submit Claim")
        if submitted:
            if amount <= 0:
                st.error("Please provide Amount")
            else:
                uid = make_uid()
                claim = Claim(
                    uid=uid,
                    submitter_id=current_user.id,
                    location=location,
                    # bill_no intentionally not populated (removed from UI)
                    claim_type=claim_type,
                    amount=amount,
                    date_of_bill=str(date_of_bill),
                    remarks=remarks,
                    status="pending",
                    current_stage="Diarist",
                )
                db.add(claim)
                db.commit()
                db.add(
                    WorkflowLog(
                        claim_id=claim.id,
                        stage="Employee",
                        action="Submitted",
                        remarks="Initial submission",
                        acted_by=current_user.id,
                    )
                )
                db.commit()
                st.success(f"Claim submitted with UID: {uid}")
    db.close()
    st.stop()

# -----------------------
# My Claims
# -----------------------
if choice == "My Claims":
    st.header("My Claims")
    rows = (
        db.query(Claim)
        .filter(Claim.submitter_id == current_user.id, Claim.archived == False)
        .order_by(Claim.created_at.desc())
        .all()
    )
    if not rows:
        st.info("No claims found.")
    else:
        for r in rows:
            submitter = db.query(User).get(r.submitter_id)
            submitter_name = submitter.name if submitter else "Deleted user"
            st.markdown(
                f"**UID:** {r.uid}  |  **Type:** {r.claim_type}  |  **Amount:** {r.amount}  | **Status:** {r.status} | **Stage:** {r.current_stage}"
            )
            st.write(f"Submitted: {r.created_at} | Location: {r.location} | Bill No: {r.bill_no or 'N/A'}")
            st.write(f"Submitter: {submitter_name}")
            st.write(f"Remarks: {r.remarks}")
            logs = db.query(WorkflowLog).filter(WorkflowLog.claim_id == r.id).order_by(WorkflowLog.timestamp).all()
            if logs:
                df = pd.DataFrame(
                    [
                        {
                            "stage": L.stage,
                            "action": L.action,
                            "remarks": L.remarks,
                            "acted_by": (db.query(User).get(L.acted_by).name if db.query(User).get(L.acted_by) else "System"),
                            "timestamp": L.timestamp,
                        }
                        for L in logs
                    ]
                )
                st.dataframe(df)
            col1, col2 = st.columns([1, 1])
            with col1:
                if st.button(f"Archive {r.uid}", key=f"arc_{r.id}"):
                    r.archived = True
                    r.status = "archived"
                    db.add(
                        WorkflowLog(
                            claim_id=r.id,
                            stage="System",
                            action="Archived",
                            remarks=f"Archived by {current_user.name}",
                            acted_by=current_user.id,
                        )
                    )
                    db.commit()
                    st.success("Archived")
            with col2:
                if st.button(f"Delete (archive) {r.uid}", key=f"del_{r.id}"):
                    txt = st.text_input("Delete remarks (required)", key=f"del_txt_{r.id}")
                    if txt and len(txt.strip()) > 2:
                        r.archived = True
                        r.deleted_by = current_user.email
                        r.deleted_remarks = txt
                        r.deleted_at = datetime.now()
                        db.add(
                            WorkflowLog(
                                claim_id=r.id,
                                stage="System",
                                action="Deleted",
                                remarks=f"Deleted by {current_user.email}: {txt}",
                                acted_by=current_user.id,
                            )
                        )
                        db.commit()
                        st.success("Deleted (archived)")
                    else:
                        st.error("Please provide delete remarks")
    db.close()
    st.stop()

# -----------------------
# Pending With Me (with forward/send-back dropdowns) - location-aware
# -----------------------
if choice == "Pending With Me":
    st.header("Claims Pending With Me")
    user_roles = current_user.role or ""
    roles = [r.strip() for r in user_roles.split(",") if r.strip()]
    my_roles = [r for r in roles if r in WORKFLOW_CHAIN]
    if not my_roles:
        st.info("You have no approver roles assigned. Use 'My Claims' if you are a claimant.")
    else:
        for role_item in my_roles:
            st.subheader(f"As {role_item} — items at your stage (Location: {current_user.location})")
            q = db.query(Claim).filter(Claim.current_stage == role_item, Claim.archived == False)
            if not has_role(current_user.role, "DG"):
                q = q.filter(Claim.location == current_user.location)
            rows = q.order_by(Claim.created_at).all()
            if not rows:
                st.write("No items.")
            for r in rows:
                submitter = db.query(User).get(r.submitter_id)
                submitter_name = submitter.name if submitter else "Deleted user"
                st.markdown(
                    f"**UID:** {r.uid} | **Type:** {r.claim_type} | **Amount:** {r.amount} | Submitted: {r.created_at}"
                )
                st.write(f"Submitter: {submitter_name} | Location: {r.location}")
                st.write(f"Bill No: {r.bill_no or 'N/A'} | Remarks: {r.remarks}")
                logs = db.query(WorkflowLog).filter(WorkflowLog.claim_id == r.id).order_by(WorkflowLog.timestamp).all()
                if logs:
                    df = pd.DataFrame(
                        [
                            {
                                "stage": L.stage,
                                "action": L.action,
                                "acted_by": (db.query(User).get(L.acted_by).name if db.query(User).get(L.acted_by) else "System"),
                                "timestamp": L.timestamp,
                                "remarks": L.remarks,
                            }
                            for L in logs
                        ]
                    )
                    st.dataframe(df)
                # form for actions with dropdowns
                with st.form(f"act_{r.id}"):
                    if role_item in ["Director"] or has_role(current_user.role, "DG"):
                        action_options = ["Forward for approval", "Send back for review", "Mark Approved (complete)"]
                    else:
                        action_options = ["Forward for approval", "Send back for review"]
                    action = st.selectbox("Action", action_options, key=f"actsel_{r.id}")
                    remarks = st.text_area("Remarks (required, min 3 chars)", max_chars=800, key=f"actrem_{r.id}")

                    # dynamic routing dropdowns
                    forward_to = None
                    send_back_to = None
                    if action == "Forward for approval":
                        higher = get_higher_roles(role_item)
                        if higher:
                            forward_to = st.selectbox("Forward to (choose higher/next)", ["Next: " + (get_next_role(role_item) or "")] + higher, key=f"fwdto_{r.id}")
                            if forward_to and forward_to.startswith("Next: "):
                                forward_to = get_next_role(role_item)
                    elif action == "Send back for review":
                        lower = get_lower_roles(role_item)
                        send_back_to = st.selectbox("Send back to (choose lower role or Claimant)", lower, key=f"sendto_{r.id}")

                    submitted = st.form_submit_button("Confirm")
                    if submitted:
                        if not remarks or len(remarks.strip()) < 3:
                            st.error("Please enter remarks (min 3 chars)")
                        else:
                            if action == "Forward for approval":
                                target = forward_to or get_next_role(role_item)
                                if not target:
                                    r.current_stage = "AwaitingPayment"
                                    r.status = "Approved (sent to PAO)"
                                    db.add(WorkflowLog(claim_id=r.id, stage=role_item, action=f"Forwarded to AwaitingPayment", remarks=remarks, acted_by=current_user.id))
                                    db.commit()
                                    st.success("Forwarded to AwaitingPayment (no higher role)")
                                else:
                                    r.current_stage = target
                                    r.status = "In Progress"
                                    db.add(WorkflowLog(claim_id=r.id, stage=role_item, action=f"Forwarded to {target}", remarks=remarks, acted_by=current_user.id))
                                    db.commit()
                                    st.success(f"Forwarded to {target}")

                            elif action == "Send back for review":
                                target = send_back_to or get_prev_role(role_item) or "Diarist"
                                if target == "Claimant":
                                    r.current_stage = "Employee"
                                    r.status = "Returned"
                                    db.add(WorkflowLog(claim_id=r.id, stage=role_item, action=f"Returned to Claimant", remarks=remarks, acted_by=current_user.id))
                                    db.commit()
                                    st.success("Returned to Claimant (submitter) for clarification")
                                else:
                                    r.current_stage = target
                                    r.status = "Returned"
                                    db.add(WorkflowLog(claim_id=r.id, stage=role_item, action=f"Returned to {target}", remarks=remarks, acted_by=current_user.id))
                                    db.commit()
                                    st.success(f"Returned to {target}")

                            elif action == "Mark Approved (complete)":
                                if role_item == "Director" or has_role(current_user.role, "DG"):
                                    next_role = get_next_role(role_item)
                                    if next_role:
                                        r.current_stage = next_role
                                        r.status = "In Progress"
                                    else:
                                        r.current_stage = "AwaitingPayment"
                                        r.status = "Approved (sent to PAO)"
                                    db.add(WorkflowLog(claim_id=r.id, stage=role_item, action="Approved", remarks=remarks, acted_by=current_user.id))
                                    db.commit()
                                    st.success("Approved (moved forward)") 
                                else:
                                    st.error("Not authorized to approve")
    db.close()
    st.stop()

# -----------------------
# Processed Items (what crossed this role)
# -----------------------
if choice == "Processed Items":
    st.header("Processed Items (that crossed your level)")
    roles_for_user = [r.strip() for r in (current_user.role or "").split(",") if r.strip()]
    if not roles_for_user:
        st.info("No roles assigned.")
    else:
        logs_query = db.query(WorkflowLog).filter(WorkflowLog.stage.in_(roles_for_user)).order_by(WorkflowLog.timestamp.desc()).limit(500)
        rows = []
        for L in logs_query.all():
            claim = db.query(Claim).get(L.claim_id)
            if not claim:
                continue
            if not has_role(current_user.role, "DG") and claim.location != current_user.location:
                continue
            submitter = db.query(User).get(claim.submitter_id)
            submitter_name = submitter.name if submitter else "Deleted user"
            rows.append(
                {
                    "claim_uid": claim.uid,
                    "stage": L.stage,
                    "action": L.action,
                    "acted_by": (db.query(User).get(L.acted_by).name if db.query(User).get(L.acted_by) else "System"),
                    "timestamp": L.timestamp,
                    "remarks": L.remarks,
                    "location": claim.location,
                    "submitter": submitter_name,
                }
            )
        if not rows:
            st.info("No processed items for your location/roles.")
        else:
            st.dataframe(pd.DataFrame(rows))
    db.close()
    st.stop()

# -----------------------
# Dashboard (Director & DG only)
# -----------------------
if choice == "Dashboard":
    if not (has_role(current_user.role, "Director") or has_role(current_user.role, "DG")):
        st.error("Dashboard restricted to Director and DG")
        st.stop()

    st.header("Dashboard (Director / DG)")
    cols = st.columns(4)
    with cols[0]:
        if has_role(current_user.role, "DG"):
            loc_filter = st.selectbox("Location", ["All", "New Delhi", "Mumbai", "Kolkata", "Chennai", "Bangalore"])
        else:
            loc_filter = st.selectbox("Location", [current_user.location])
    with cols[1]:
        type_filter = st.selectbox("Claim Type", ["All", "Medical", "Travel", "LTC", "Office Advance", "Other"])
    with cols[2]:
        days_pending = st.number_input("Min days pending", min_value=0, value=0)
    with cols[3]:
        stage_filter = st.selectbox("Stage", ["All"] + WORKFLOW_CHAIN + ["AwaitingPayment", "Closed", "Returned", "Archived"])

    query = db.query(Claim).filter(Claim.archived == False)
    if loc_filter != "All":
        query = query.filter(Claim.location == loc_filter)
    if type_filter != "All":
        query = query.filter(Claim.claim_type == type_filter)
    if stage_filter != "All":
        query = query.filter(Claim.current_stage == stage_filter)

    rows = query.all()
    data = []
    for r in rows:
        submitter = db.query(User).get(r.submitter_id)
        submitter_name = submitter.name if submitter else "Deleted user"
        days = (datetime.now() - (r.created_at or datetime.now())).days
        if days >= days_pending:
            data.append(
                {
                    "uid": r.uid,
                    "type": r.claim_type,
                    "amount": r.amount,
                    "status": r.status,
                    "stage": r.current_stage,
                    "created_at": r.created_at,
                    "location": r.location,
                    "submitter": submitter_name,
                }
            )
    if not data:
        st.info("No claims match filters.")
    else:
        df = pd.DataFrame(data)
        st.dataframe(df)
        st.subheader("Claims by Stage")
        fig = px.histogram(df, x="stage", title="Claims by Current Stage")
        st.plotly_chart(fig)

        st.subheader("Average processing time per role (estimate)")
        logs = pd.read_sql(db.query(WorkflowLog).statement, db.bind)
        if not logs.empty:
            logs["timestamp"] = pd.to_datetime(logs["timestamp"])
            logs_sorted = logs.sort_values(["claim_id", "timestamp"])
            logs_sorted["prev_ts"] = logs_sorted.groupby("claim_id")["timestamp"].shift(1)
            logs_sorted["delta_days"] = (logs_sorted["timestamp"] - logs_sorted["prev_ts"]).dt.total_seconds() / 86400
            avg = logs_sorted.groupby("stage")["delta_days"].mean().reset_index().dropna()
            if not avg.empty:
                st.dataframe(avg)
            else:
                st.info("Not enough workflow history yet.")

    st.subheader("Drill down to UID")
    uid = st.text_input("Enter UID")
    if st.button("Lookup UID"):
        claim = db.query(Claim).filter(Claim.uid == uid).first()
        if not claim:
            st.error("UID not found")
        else:
            if not has_role(current_user.role, "DG") and claim.location != current_user.location:
                st.error("Not authorized to view this claim (different location)")
            else:
                submitter = db.query(User).get(claim.submitter_id)
                submitter_name = submitter.name if submitter else "Deleted user"
                st.write(
                    f"UID {claim.uid} | Type: {claim.claim_type} | Amount: {claim.amount} | Stage: {claim.current_stage} | Status: {claim.status} | Location: {claim.location} | Submitter: {submitter_name}"
                )
                logs = db.query(WorkflowLog).filter(WorkflowLog.claim_id == claim.id).order_by(WorkflowLog.timestamp).all()
                df = pd.DataFrame(
                    [
                        {
                            "stage": L.stage,
                            "action": L.action,
                            "remarks": L.remarks,
                            "acted_by": (db.query(User).get(L.acted_by).name if db.query(User).get(L.acted_by) else "System"),
                            "timestamp": L.timestamp,
                        }
                        for L in logs
                    ]
                )
                st.dataframe(df)

    db.close()
    st.stop()

# -----------------------
# End of app (cleanup)
# -----------------------
db.close()
st.write("---")
st.caption("ClaimTrack v3 — update: removed bill number from submission; added admin user deactivation (soft-delete).")