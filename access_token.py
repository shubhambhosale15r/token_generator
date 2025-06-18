import streamlit as st
from fyers_apiv3 import fyersModel
import urllib.parse

st.set_page_config(page_title="Fyers OAuth2 Secure Flow", layout="centered")
st.title("🔐 Fyers OAuth2 Authentication")

REDIRECT_URI = "https://www.google.com/"
GRANT_TYPE = "authorization_code"
RESPONSE_TYPE = "code"
STATE = "sample_state_123"

# --- Step 1: Always show input for credentials ---
CLIENT_ID = st.text_input("Enter Client ID (e.g., ABC123-100):")
SECRET_KEY = st.text_input("Enter Secret Key:", type="password")

if CLIENT_ID and SECRET_KEY:
    # Button to generate Auth URL
    if st.button("Generate Authorization URL"):
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
        st.markdown(f"[Click here to authorize]({auth_url})", unsafe_allow_html=True)
        st.session_state['session_obj'] = session
        st.session_state['client_id'] = CLIENT_ID
        st.session_state['secret_key'] = SECRET_KEY

    # Step 2: Paste auth code URL or code
    auth_response = st.text_input("Paste redirected URL or auth code here:")

    if st.button("Generate Access Token"):
        if 'session_obj' not in st.session_state:
            st.error("Generate authorization URL first.")
        elif not auth_response:
            st.error("Paste the redirected URL or code here.")
        else:
            session = st.session_state['session_obj']

            # Parse the code from full URL if pasted
            parsed = urllib.parse.urlparse(auth_response)
            params = urllib.parse.parse_qs(parsed.query)
            code = params.get("code", [auth_response])[0]

            # st.write(f"Extracted code: `{code}`")

            session.set_token(code)
            token_response = session.generate_token()
            # st.write("Token response:", token_response)

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
