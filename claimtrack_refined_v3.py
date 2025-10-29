# ==============================================================
# ClaimTrack v3 — FINAL VERSION
# Awaiting Budget (Auditor/AAO/SAO) + Enhanced Dashboard
# ==============================================================

import os
import random
import string
import time
from datetime import datetime
import pandas as pd
import plotly.express as px
import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, Boolean, ForeignKey, func
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- CONFIG -----------------
DEFAULT_SQLITE = "sqlite:///data/claims_refined_v3.db"
DB_URL = os.environ.get("DATABASE_URL", DEFAULT_SQLITE)
os.makedirs("data", exist_ok=True)
engine = create_engine(DB_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# Roles chain
WORKFLOW_CHAIN = ["Diarist", "Auditor", "AAO", "SAO", "Director", "DDO"]
AWAITING_ROLES = ["Auditor", "AAO", "SAO"]

# ---------------- MODELS -----------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    email = Column(String)
    password_hash = Column(String)
    role = Column(String)
    location = Column(String)
    phone = Column(String)
    official_id = Column(String)
    is_admin = Column(Boolean, default=False)
    active = Column(Boolean, default=True)

class Claim(Base):
    __tablename__ = "claims"
    id = Column(Integer, primary_key=True)
    uid = Column(String, unique=True, index=True)
    submitter_id = Column(Integer, ForeignKey("users.id"))
    submitter = relationship("User", foreign_keys=[submitter_id])
    claim_type = Column(String)
    amount = Column(Float)
    date_of_bill = Column(String)
    remarks = Column(Text)
    created_at = Column(DateTime, default=func.now())
    status = Column(String, default="Pending")
    current_stage = Column(String, default="Diarist")
    location = Column(String)
    archived = Column(Boolean, default=False)

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

# ---------------- HELPERS -----------------
def get_db():
    return SessionLocal()

def make_uid():
    return "CT-" + datetime.now().strftime("%Y%m%d") + "-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=5))

def has_role(user_roles, role):
    if not user_roles:
        return False
    roles = [r.strip() for r in user_roles.split(",")]
    return role in roles or "Admin" in roles

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

# ---------------- STREAMLIT CONFIG -----------------
st.set_page_config(page_title="ClaimTrack v3", layout="wide")
st.title("ClaimTrack — Awaiting Budget Enabled")

if "user" not in st.session_state:
    st.session_state["user"] = None

# Seed admin
db = get_db()
if not db.query(User).filter(User.email == "admin@org.in").first():
    admin = User(
        name="Admin",
        email="admin@org.in",
        password_hash=generate_password_hash("admin123"),
        role="Admin",
        location="New Delhi",
        is_admin=True,
    )
    db.add(admin)
    db.commit()
db.close()

# ---------------- LOGIN -----------------
def login():
    st.subheader("Login")
    email = st.text_input("Email")
    pwd = st.text_input("Password", type="password")
    if st.button("Login"):
        db = get_db()
        user = db.query(User).filter(User.email == email, User.active == True).first()
        if user and check_password_hash(user.password_hash, pwd):
            st.session_state["user"] = {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role,
                "location": user.location,
                "is_admin": user.is_admin,
            }
            st.success("✅ Login successful! Redirecting...")
            time.sleep(1)
            st.rerun()
        else:
            st.error("Invalid credentials")
        db.close()

def signup():
    st.subheader("Claimant Sign-Up")
    name = st.text_input("Full name")
    email = st.text_input("Email")
    pwd = st.text_input("Password", type="password")
    loc = st.selectbox("Location", ["New Delhi", "Mumbai", "Kolkata", "Chennai", "Bangalore"])
    if st.button("Sign Up"):
        db = get_db()
        if db.query(User).filter(User.email == email).first():
            st.error("Email already exists")
        else:
            u = User(
                name=name, email=email,
                password_hash=generate_password_hash(pwd),
                role="Claimant", location=loc
            )
            db.add(u)
            db.commit()
            st.success("Account created successfully!")
        db.close()

if not st.session_state["user"]:
    col1, col2 = st.columns(2)
    with col1:
        login()
    with col2:
        signup()
    st.stop()

db = get_db()
user = db.query(User).get(st.session_state["user"]["id"])

# Sidebar
menu = ["Submit Claim", "My Claims", "Pending With Me"]
if has_role(user.role, "Director") or has_role(user.role, "DG"):
    menu.append("Dashboard")
if user.is_admin:
    menu.append("Admin")

choice = st.sidebar.selectbox("Menu", menu)
st.sidebar.info(f"{user.name} ({user.role}) - {user.location}")
if st.sidebar.button("Logout"):
    st.session_state.clear()
    st.success("✅ Successfully logged out!")
    time.sleep(1)
    st.rerun()

# ---------------- ADMIN -----------------
if choice == "Admin":
    if not user.is_admin:
        st.error("Admin only")
        st.stop()
    st.header("Admin Panel")
    st.subheader("Create/Assign Roles")
    name = st.text_input("Name")
    email = st.text_input("Email")
    pwd = st.text_input("Password", type="password")
    role = st.selectbox("Role", ["Diarist","Auditor","AAO","SAO","Director","DDO","Claimant"])
    loc = st.selectbox("Location", ["New Delhi","Mumbai","Kolkata","Chennai","Bangalore"])
    if st.button("Add User"):
        if not email or not pwd:
            st.error("Email and password required")
        else:
            existing = db.query(User).filter(User.email == email).first()
            if existing:
                st.warning("User already exists; role updated.")
                existing.role = role
                db.commit()
            else:
                db.add(User(
                    name=name or email, email=email,
                    password_hash=generate_password_hash(pwd),
                    role=role, location=loc))
                db.commit()
                st.success("User added.")

    st.markdown("---")
    st.subheader("Reset Password")
    reset_email = st.text_input("Email to reset")
    new_pwd = st.text_input("New password", type="password")
    if st.button("Reset Password"):
        target = db.query(User).filter(User.email == reset_email).first()
        if target:
            target.password_hash = generate_password_hash(new_pwd)
            db.commit()
            st.success("Password reset successfully")
        else:
            st.error("User not found")

    st.markdown("---")
    st.subheader("Deactivate User")
    users = db.query(User).filter(User.active == True, User.is_admin == False).all()
    names = [f"{u.name} ({u.email})" for u in users]
    sel = st.selectbox("Select user to deactivate", names)
    if st.button("Deactivate"):
        for u in users:
            if f"{u.name} ({u.email})" == sel:
                u.active = False
                u.name = "Deleted user"
                u.email = f"deleted_{u.id}@disabled.local"
                u.role = ""
                db.commit()
                st.success("User deactivated.")
    st.stop()

# ---------------- SUBMIT CLAIM -----------------
if choice == "Submit Claim":
    st.header("Submit New Claim")
    with st.form("new_claim"):
        ctype = st.selectbox("Claim Type", ["Medical","Travel","LTC","Office Advance","Other"])
        amt = st.number_input("Amount", min_value=0.0)
        dob = st.date_input("Bill Date")
        remarks = st.text_area("Remarks (optional)")
        submit = st.form_submit_button("Submit Claim")
        if submit:
            if amt <= 0:
                st.error("Amount required")
            else:
                uid = make_uid()
                new_claim = Claim(
                    uid=uid, submitter_id=user.id, claim_type=ctype,
                    amount=amt, date_of_bill=str(dob),
                    remarks=remarks, location=user.location,
                    status="Pending", current_stage="Diarist")
                db.add(new_claim)
                db.commit()
                st.success(f"Claim submitted successfully (UID: {uid})")
    st.stop()

# ---------------- MY CLAIMS -----------------
if choice == "My Claims":
    st.header("My Claims")
    claims = db.query(Claim).filter(Claim.submitter_id == user.id).order_by(Claim.created_at.desc()).all()
    if not claims:
        st.info("No claims yet.")
    else:
        for c in claims:
            status = c.status
            if c.current_stage == "Awaiting Budget":
                status = "🟠 Awaiting Budget (funds not available)"
            st.markdown(f"**UID:** {c.uid} | **Type:** {c.claim_type} | **Amount:** {c.amount} | **Stage:** {c.current_stage} | **Status:** {status}")

# ---------------- PENDING WITH ME -----------------
if choice == "Pending With Me":
    st.header("Claims Pending With Me")
    roles = [r.strip() for r in (user.role or "").split(",")]
    for role in roles:
        if role not in WORKFLOW_CHAIN: 
            continue
        st.subheader(f"As {role}")
        q = db.query(Claim).filter(Claim.current_stage.in_([role, "Awaiting Budget"]), Claim.location == user.location).all()
        if not q:
            st.info(f"No pending claims for {role}.")
        for c in q:
            st.markdown(f"**UID:** {c.uid} | **Type:** {c.claim_type} | **Amount:** {c.amount} | **Stage:** {c.current_stage}")
            remarks = st.text_area("Remarks", key=f"r_{c.id}")
            actions = ["Forward for approval","Send back for review"]
            if role in ["Director","DG"]:
                actions.append("Approve (Complete)")
            if role in AWAITING_ROLES or has_role(user.role, "DG"):
                if c.current_stage != "Awaiting Budget":
                    actions.append("Mark Awaiting Budget")
                else:
                    actions.append("Unpark and Forward")
            act = st.selectbox("Action", actions, key=f"a_{c.id}")
            if st.button("Confirm", key=f"b_{c.id}"):
                if not remarks:
                    st.error("Remarks required")
                else:
                    if act == "Forward for approval":
                        nxt = get_next_role(role)
                        c.current_stage = nxt or "AwaitingPayment"
                        c.status = "In Progress"
                        db.add(WorkflowLog(claim_id=c.id, stage=role, action=f"Forwarded to {nxt}", remarks=remarks, acted_by=user.id))
                        db.commit()
                        st.success(f"Forwarded to {nxt or 'AwaitingPayment'}")
                    elif act == "Send back for review":
                        prv = get_prev_role(role)
                        c.current_stage = prv or "Employee"
                        c.status = "Returned"
                        db.add(WorkflowLog(claim_id=c.id, stage=role, action=f"Returned to {prv}", remarks=remarks, acted_by=user.id))
                        db.commit()
                        st.success(f"Returned to {prv}")
                    elif act == "Mark Awaiting Budget":
                        c.current_stage = "Awaiting Budget"
                        c.status = "Awaiting Budget"
                        db.add(WorkflowLog(claim_id=c.id, stage=role, action="Marked Awaiting Budget", remarks=remarks, acted_by=user.id))
                        db.commit()
                        st.success("Claim parked as Awaiting Budget")
                    elif act == "Unpark and Forward":
                        nxt = get_next_role(role)
                        c.current_stage = nxt or "DDO"
                        c.status = "In Progress"
                        db.add(WorkflowLog(claim_id=c.id, stage=role, action=f"Unparked and Forwarded to {nxt or 'DDO'}", remarks=remarks, acted_by=user.id))
                        db.commit()
                        st.success("Claim unparked and forwarded")
                    elif act == "Approve (Complete)":
                        c.current_stage = "DDO"
                        c.status = "Approved"
                        db.add(WorkflowLog(claim_id=c.id, stage=role, action="Approved", remarks=remarks, acted_by=user.id))
                        db.commit()
                        st.success("Approved and moved to DDO")

# ---------------- DASHBOARD -----------------
if choice == "Dashboard":
    if not (has_role(user.role, "Director") or has_role(user.role, "DG")):
        st.error("Dashboard restricted.")
        st.stop()
    st.header("Dashboard")
    cols = st.columns(4)
    with cols[0]:
        loc = st.selectbox("Location", ["All","New Delhi","Mumbai","Kolkata","Chennai","Bangalore"])
    with cols[1]:
        ctype = st.selectbox("Claim Type", ["All","Medical","Travel","LTC","Office Advance","Other"])
    with cols[2]:
        stage = st.selectbox("Stage", ["All"] + WORKFLOW_CHAIN + ["Awaiting Budget","Returned","Approved"])
    with cols[3]:
        min_days = st.number_input("Min Days Pending", min_value=0, value=0)
    q = db.query(Claim).filter(Claim.archived == False)
    if loc != "All": q = q.filter(Claim.location == loc)
    if ctype != "All": q = q.filter(Claim.claim_type == ctype)
    if stage != "All": q = q.filter(Claim.current_stage == stage)
    claims = q.all()
    data = []
    for c in claims:
        days = (datetime.now() - c.created_at).days
        if days >= min_days:
            data.append({"UID":c.uid,"Type":c.claim_type,"Amount":c.amount,"Stage":c.current_stage,"Status":c.status,"Location":c.location,"Days":days})
    if not data:
        st.info("No matching claims.")
    else:
        df = pd.DataFrame(data)
        tab1, tab2 = st.tabs(["📋 Summary","📊 Visuals"])
        with tab1:
            st.dataframe(df)
        with tab2:
            df["flag"] = df["Stage"].apply(lambda x: "Awaiting Budget" if x=="Awaiting Budget" else "Other")
            fig1 = px.bar(df, x="Stage", color="flag", title="Claims by Stage (🟠 Awaiting Budget Highlighted)")
            st.plotly_chart(fig1)
            fig2 = px.pie(df, names="Type", title="Claims by Type")
            st.plotly_chart(fig2)
            fig3 = px.bar(df, x="Location", y="Amount", title="Total Amount by Location")
            st.plotly_chart(fig3)

st.caption("ClaimTrack v3 — Awaiting Budget (Auditor/AAO/SAO) + Enhanced Dashboard Visuals")
