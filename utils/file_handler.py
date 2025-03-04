# utils/file_handler.py
import os
from pathlib import Path

import aiofiles
from fastapi import UploadFile


async def process_uploaded_file(file: UploadFile) -> str:
    """
    Process an uploaded file and return its contents

    Args:
        file: The uploaded file object

    Returns:
        str: The contents of the file

    Raises:
        ValueError: If the file is empty or too large
        IOError: If there's an error reading the file
    """

    if not file.filename:
        raise ValueError("No file uploaded")

    # Check file size (limit to 10MB)
    MAX_SIZE = 10 * 1024 * 1024  # 10MB
    file_size = 0
    contents = []

    try:
        # Read file in chunks to handle large files
        chunk_size = 8192  # 8KB chunks
        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break
            file_size += len(chunk)
            if file_size > MAX_SIZE:
                raise ValueError("File too large (max 10MB)")
            contents.append(chunk.decode())

        return "".join(contents)

    except UnicodeDecodeError:
        raise ValueError("File must be a text file")
    except Exception as e:
        raise IOError(f"Error reading file: {str(e)}")
    finally:
        await file.seek(0)  # Reset file pointer for potential future reads

async def save_uploaded_file(file: UploadFile, directory: str) -> Path:
    """
    Save an uploaded file to disk

    Args:
        file: The uploaded file object
        directory: Directory to save the file in

    Returns:
        Path: Path to the saved file

    Raises:
        IOError: If there's an error saving the file
    """

    # Create directory if it doesn't exist
    os.makedirs(directory, exist_ok=True)

    file_path = Path(directory) / file.filename
    try:
        async with aiofiles.open(file_path, 'wb') as f:
            while chunk := await file.read(8192):
                await f.write(chunk)
        return file_path
    except Exception as e:
        raise IOError(f"Error saving file: {str(e)}")
    finally:
        await file.seek(0)