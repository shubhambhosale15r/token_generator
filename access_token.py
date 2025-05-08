import streamlit as st
import webbrowser
from fyers_apiv3 import fyersModel

# Constants - Replace with your own values
REDIRECT_URI = "https://www.google.com/"  # Ideally, use a localhost URI for dev
CLIENT_ID = "0F5WWD1SBL-100"
SECRET_KEY = "5EME8IYZ76"
GRANT_TYPE = "authorization_code"
RESPONSE_TYPE = "code"
STATE = "sample"

st.set_page_config(page_title="Fyers OAuth App", layout="centered")
st.title("🔐 Fyers API OAuth2 Authentication")

# Step 1: Generate Auth URL
if st.button("🔗 Generate Authorization URL"):
    session = fyersModel.SessionModel(
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        response_type=RESPONSE_TYPE,
        state=STATE,
        secret_key=SECRET_KEY,
        grant_type=GRANT_TYPE
    )
    auth_url = session.generate_authcode()
    st.success("Authorization URL generated!")
    st.markdown(f"[Click here to Authorize]({auth_url})", unsafe_allow_html=True)
    st.session_state['session_obj'] = session

# Step 2: User inputs authorization code
auth_code = st.text_input("Paste the authorization code here (from URL after login):")

if st.button("✅ Generate Access Token"):
    if not auth_code:
        st.error("Please paste the authorization code first.")
    elif 'session_obj' not in st.session_state:
        st.error("Please generate the authorization URL first.")
    else:
        session = st.session_state['session_obj']
        session.set_token(auth_code)
        response = session.generate_token()
        if "access_token" in response:
            access_token = response["access_token"]
            st.session_state['access_token'] = access_token
            st.success("Access Token generated successfully!")
            st.code(access_token, language='text')
        else:
            st.error(f"Failed to get token: {response}")

# Step 3: Make API calls
if 'access_token' in st.session_state:
    st.subheader("📊 Fyers Account Details")
    fyers = fyersModel.FyersModel(
        token=st.session_state['access_token'],
        is_async=False,
        client_id=CLIENT_ID,
        log_path=""
    )

    if st.button("👤 Get Profile"):
        profile = fyers.get_profile()
        st.json(profile)

    if st.button("💰 Get Funds"):
        funds = fyers.funds()
        st.json(funds)

    if st.button("📈 Get Holdings"):
        holdings = fyers.holdings()
        st.json(holdings)
