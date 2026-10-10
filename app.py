import streamlit as st

from lib.auth import require_user

st.set_page_config(page_title="App", page_icon=":material/school:")
st.title("App")

user = require_user()
st.text(user.email)
if st.button("ログアウト", icon=":material/logout:"):
    st.logout()

# Add the team's protected application here.
