import streamlit as st
from fyers_apiv3 import fyersModel

st.set_page_config(page_title="Fyers OAuth2 Secure Flow", layout="centered")
st.title("🔐 Fyers OAuth2 Authentication")

REDIRECT_URI = "https://tokengeneratorfyers.streamlit.app/"
GRANT_TYPE = "authorization_code"
RESPONSE_TYPE = "code"
STATE = "sample_state_123"

CLIENT_ID = st.text_input("Enter Client ID (e.g., ABC123-100):")
SECRET_KEY = st.text_input("Enter Secret Key:", type="password")

if CLIENT_ID and SECRET_KEY:
    # Initialize session model once client details are available
    if 'session_obj' not in st.session_state:
        session = fyersModel.SessionModel(
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            response_type=RESPONSE_TYPE,
            state=STATE,
            secret_key=SECRET_KEY,
            grant_type=GRANT_TYPE
        )
        st.session_state['session_obj'] = session
        st.session_state['client_id'] = CLIENT_ID
        st.session_state['secret_key'] = SECRET_KEY
    else:
        session = st.session_state['session_obj']

    # Step 1: Generate authorization URL
    if st.button("Generate Authorization URL"):
        auth_url = session.generate_authcode()
        st.success("Authorization URL generated!")
        st.markdown(f"[Click here to authorize]({auth_url})", unsafe_allow_html=True)

    # Step 2: Automatically get auth_code from URL query params using st.query_params
    params = st.query_params
    auth_code = params.get("auth_code", [None])[0]

    if auth_code:
        st.success(f"Authorization code detected: `{auth_code}`")

        # Only generate token if not already generated or token missing
        if 'access_token' not in st.session_state:
            session.set_token(auth_code)
            token_response = session.generate_token()
            st.write("Token Response:")
            st.json(token_response)

            if "access_token" in token_response:
                st.session_state['access_token'] = token_response["access_token"]
                st.success("Access token generated!")
                st.code(token_response["access_token"], language="text")
            else:
                st.error(f"Failed to generate token: {token_response}")

    # Step 3: Use token to call APIs
    if 'access_token' in st.session_state:
        fyers = fyersModel.FyersModel(
            token=st.session_state['access_token'],
            is_async=False,
            client_id=st.session_state['client_id'],
            log_path=""
        )

        st.subheader("📊 API Actions")

        if st.button("Get Profile"):
            profile = fyers.get_profile()
            st.json(profile)

        if st.button("Get Funds"):
            funds = fyers.funds()
            st.json(funds)

        if st.button("Get Holdings"):
            holdings = fyers.holdings()
            st.json(holdings)
else:
    st.info("Please enter Client ID and Secret Key to start.")
