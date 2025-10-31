import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime
import plotly.express as px
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------------
# DB SETUP
# -----------------------------
conn = sqlite3.connect("claims.db", check_same_thread=False)
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT,
    location TEXT
)''')

c.execute('''CREATE TABLE IF NOT EXISTS claims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    type TEXT,
    bill_no TEXT,
    amount REAL,
    bill_date TEXT,
    remarks TEXT,
    status TEXT,
    current_role TEXT,
    location TEXT,
    created_at TEXT
)''')

c.execute('''CREATE TABLE IF NOT EXISTS workflow (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    claim_id INTEGER,
    role TEXT,
    action TEXT,
    remarks TEXT,
    timestamp TEXT
)''')

conn.commit()

# -----------------------------
# HELPERS
# -----------------------------
def get_user(email):
    c.execute("SELECT * FROM users WHERE email=?", (email,))
    return c.fetchone()

def get_pending_claims(role, location):
    if role in ["Director", "DDO", "DG"]:
        c.execute("SELECT * FROM claims WHERE current_role=? AND status!='Completed'", (role,))
    else:
        c.execute("SELECT * FROM claims WHERE current_role=? AND location=? AND status!='Completed'", (role, location))
    return c.fetchall()

def submit_claim(user_id, claim_type, bill_no, amount, bill_date, remarks, location):
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO claims (user_id,type,bill_no,amount,bill_date,remarks,status,current_role,location,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (user_id, claim_type, bill_no, amount, bill_date, remarks, "Pending", "Diarist", location, created_at)
    )
    conn.commit()
    st.success("✅ Claim submitted successfully!")

def process_claim(claim_id, action, remarks, next_role=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO workflow (claim_id,role,action,remarks,timestamp) VALUES (?,?,?,?,?)",
              (st.session_state['user']['role'], st.session_state['user']['role'], action, remarks, timestamp))
    if action == "Approved" and not next_role:
        c.execute("UPDATE claims SET status='Completed',current_role=NULL WHERE id=?", (claim_id,))
    elif action == "Returned":
        c.execute("UPDATE claims SET current_role='Claimant',status='Returned' WHERE id=?", (claim_id,))
    elif action == "Awaiting Budget":
        c.execute("UPDATE claims SET status='Awaiting Budget' WHERE id=?", (claim_id,))
    elif action == "Forwarded":
        c.execute("UPDATE claims SET current_role=?,status='In Progress' WHERE id=?", (next_role, claim_id))
    conn.commit()
    st.success(f"✅ Claim {action} successfully!")

def logout():
    st.session_state.clear()
    st.success("✅ Successfully logged out!")

# -----------------------------
# LOGIN / SIGNUP
# -----------------------------
if "user" not in st.session_state:
    st.title("DGACE-ESD ClaimTrack")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        user = get_user(email)
        if user and check_password_hash(user[3], password):
            st.session_state["user"] = {
                "id": user[0],
                "name": user[1],
                "email": user[2],
                "role": user[4],
                "location": user[5]
            }
            st.rerun()
        else:
            st.error("Invalid credentials. Try again or contact admin.")
    st.stop()

# -----------------------------
# MAIN APP
# -----------------------------
user = st.session_state["user"]
role = user["role"]
location = user["location"]

st.sidebar.header(f"Welcome, {user['name']} ({role})")
st.sidebar.write(f"📍 {location}")

# Menu visibility based on role
if role == "Claimant":
    menu = ["Submit Claim", "My Claims", "Logout"]
elif role in ["Diarist", "Auditor", "AAO", "SAO", "Director", "DDO"]:
    menu = ["Pending with Me", "Processed by Me", "Logout"]
elif role == "Admin":
    menu = ["Manage Users", "Export Data", "Logout"]
elif role == "DG":
    menu = ["Dashboard", "Logout"]
else:
    menu = ["Logout"]

choice = st.sidebar.selectbox("Navigate", menu)

# -----------------------------
# CLAIMANT SECTION
# -----------------------------
if role == "Claimant" and choice == "Submit Claim":
    st.header("🧾 Submit New Claim")

    claim_type = st.selectbox("Claim Type", ["Medical", "Travel", "LTC"], key="claim_type_new")
    bill_no = st.text_input("Bill Number", key="claim_bill_no_new")
    amount = st.number_input("Amount (₹)", min_value=0.0, key="claim_amount_new")
    bill_date = st.date_input("Bill Date", key="claim_date_new")
    remarks = st.text_area("Remarks (optional)", key="claim_remarks_new")

    if st.button("Submit Claim", key="claim_submit_new"):
        submit_claim(user["id"], claim_type, bill_no, amount, str(bill_date), remarks, location)

elif role == "Claimant" and choice == "My Claims":
    st.header("📜 My Claims")
    c.execute("SELECT id,type,bill_no,amount,status,current_role,created_at FROM claims WHERE user_id=?", (user["id"],))
    df = pd.DataFrame(c.fetchall(), columns=["ID","Type","Bill No","Amount","Status","Current Role","Created At"])
    st.dataframe(df if not df.empty else pd.DataFrame())

# -----------------------------
# OFFICIALS SECTION
# -----------------------------
elif role in ["Diarist","Auditor","AAO","SAO","Director","DDO"] and choice == "Pending with Me":
    st.header(f"📂 Pending Claims for {role}")
    claims = get_pending_claims(role, location)
    if not claims:
        st.info("No pending claims.")
    else:
        for cl in claims:
            st.subheader(f"Claim ID: {cl[0]} | ₹{cl[4]} | {cl[2]}")
            st.write(f"Bill No: {cl[3]} | Remarks: {cl[6]}")
            remarks = st.text_area(f"Remarks for Claim {cl[0]}", key=f"r_{cl[0]}")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                if st.button(f"Forward {cl[0]}", key=f"fwd_{cl[0]}"):
                    next_roles = {"Diarist":"Auditor","Auditor":"AAO","AAO":"SAO","SAO":"Director","Director":"DDO"}
                    process_claim(cl[0], "Forwarded", remarks, next_roles.get(role))
            with col2:
                if st.button(f"Return {cl[0]}", key=f"ret_{cl[0]}"):
                    process_claim(cl[0], "Returned", remarks)
            with col3:
                if role in ["Auditor","AAO","SAO"] and st.button(f"Await Budget {cl[0]}", key=f"ab_{cl[0]}"):
                    process_claim(cl[0], "Awaiting Budget", remarks)
            with col4:
                if role == "Director" and st.button(f"Approve {cl[0]}", key=f"appr_{cl[0]}"):
                    process_claim(cl[0], "Approved", remarks)

# -----------------------------
# ADMIN SECTION
# -----------------------------
elif role == "Admin" and choice == "Manage Users":
    st.header("👤 Manage Users")

    # Add User
    name = st.text_input("Name", key="admin_user_create_name")
    email = st.text_input("Email", key="admin_user_create_email")
    password = st.text_input("Password", key="admin_user_create_password", type="password")
    role_sel = st.selectbox("Role", ["Diarist","Auditor","AAO","SAO","Director","DDO","Claimant","DG"], key="admin_user_create_role")
    location_sel = st.selectbox("Location", ["New Delhi","Mumbai","Chennai","Kolkata","Bangalore"], key="admin_user_create_location")

    if st.button("Add / Update User", key="admin_user_create_button"):
        hashed_pwd = generate_password_hash(password)
        c.execute("INSERT OR REPLACE INTO users (name,email,password,role,location) VALUES (?,?,?,?,?)",
                  (name,email,hashed_pwd,role_sel,location_sel))
        conn.commit()
        st.success(f"User {name} added or updated successfully.")

    st.divider()

    # Deactivate user
    c.execute("SELECT email FROM users WHERE role!='Admin'")
    users_list = [u[0] for u in c.fetchall()]
    del_user = st.selectbox("Select user to deactivate", users_list, key="admin_user_delete_select")
    if st.button("Deactivate", key="admin_user_delete_button"):
        c.execute("DELETE FROM users WHERE email=?", (del_user,))
        conn.commit()
        st.warning(f"User {del_user} deactivated.")

elif role == "Admin" and choice == "Export Data":
    st.header("📦 Export Data")
    claims_df = pd.read_sql_query("SELECT * FROM claims", conn)
    users_df = pd.read_sql_query("SELECT * FROM users", conn)
    wf_df = pd.read_sql_query("SELECT * FROM workflow", conn)

    st.download_button("⬇️ Download Claims CSV", claims_df.to_csv(index=False), "claims.csv")
    st.download_button("⬇️ Download Users CSV", users_df.to_csv(index=False), "users.csv")
    st.download_button("⬇️ Download Workflow CSV", wf_df.to_csv(index=False), "workflow.csv")

# -----------------------------
# DG DASHBOARD
# -----------------------------
elif role == "DG" and choice == "Dashboard":
    st.header("📊 DG Dashboard (All Locations)")
    c.execute("SELECT type,status,current_role,location,created_at FROM claims")
    data = pd.DataFrame(c.fetchall(), columns=["Type","Status","Current Role","Location","Created At"])
    if not data.empty:
        location_filter = st.multiselect("Filter by Location", sorted(data["Location"].unique()), default=sorted(data["Location"].unique()))
        type_filter = st.multiselect("Filter by Claim Type", sorted(data["Type"].unique()), default=sorted(data["Type"].unique()))
        filtered = data[(data["Location"].isin(location_filter)) & (data["Type"].isin(type_filter))]
        st.dataframe(filtered)
        fig = px.histogram(filtered, x="Status", color="Type", barmode="group", title="Claims by Status and Type")
        st.plotly_chart(fig)
    else:
        st.info("No claim data available.")

# -----------------------------
# LOGOUT
# -----------------------------
elif choice == "Logout":
    logout()
