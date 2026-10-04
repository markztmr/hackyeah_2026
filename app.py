"""The demo agent and the dashboard as one Streamlit app, so one port (and one tunnel) serves both.

    streamlit run app.py                    # needs the gateway on port 8000
    ngrok http 8501 --basic-auth "demo:<password>"

Each page is its unchanged app file; ``streamlit run dashboard/app.py`` and
``streamlit run demo_agent/app.py`` still work on their own. Both pages talk to the gateway
from the server, so only this UI is exposed; the gateway and Ollama stay on localhost.
"""
import streamlit as st

st.navigation(
    [st.Page("demo_agent/app.py", title="Demo agent", icon=":material/smart_toy:", url_path="agent", default=True),
     st.Page("dashboard/app.py", title="Dashboard", icon=":material/shield:", url_path="dashboard")],
    position="top",
).run()
