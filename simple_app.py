# simple_app.py
import streamlit as st
import httpx
import asyncio

async def send_file(file):
    """
    Sends the file to the FastAPI endpoint and displays the response.
    """
    async with httpx.AsyncClient() as client:
        try:
            files = {'file': (file.name, file.getvalue(), file.type)}  # Correct file handling
            response = await client.post("http://127.0.0.1:8001/analyze", files=files) #Use correct endpoint
            response.raise_for_status()  # Raise HTTP errors
            return response.json()
        except httpx.RequestError as e:
            st.error(f"Network error: {e}")
            return None
        except httpx.HTTPStatusError as e:
            st.error(f"HTTP error: {e.response.status_code} - {e.response.text}")
            return None
        except Exception as e:
            st.error(f"Unexpected error: {e}")
            return None

st.title("Simple File Upload Test")

uploaded_file = st.file_uploader("Choose a file", type=["txt", "py"])  # Simple file types

if uploaded_file:
    st.write(f"Uploaded: {uploaded_file.name}")

    if st.button("Send to API"):
        with st.spinner("Sending file..."):
            result = asyncio.run(send_file(uploaded_file))
            if result:
                st.success("File sent successfully!")
                st.json(result)  # Display the JSON response
            #Error handling moved into the send_file function.