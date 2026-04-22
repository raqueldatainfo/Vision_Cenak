from datetime import datetime
import logging
from typing import Dict, List, Optional, Tuple, Any, AsyncIterator
import asyncio
from contextlib import asynccontextmanager
import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks, Path
from pydantic import BaseModel
import sys
from cryptography.fernet import Fernet

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class BiometricDB:
    """Banco de Dados Biométrico simulado com dados criptografados."""

    def __init__(self) -> None:
        self.key: bytes = Fernet.generate_key()
        self.cipher_suite: Fernet = Fernet(self.key)
        self.users: List[Dict[str, Any]] = []

    def register(self, user_id: str, biometric_features: str, roles: List[str]) -> None:
        """Registra um usuário com dados biométricos criptografados."""
        encrypted_biometric: bytes = self.cipher_suite.encrypt(biometric_features.encode())
        self.users.append({
            "user_id": user_id,
            "encrypted_biometric": encrypted_biometric.decode(),
            "roles": roles
        })

    def authenticate(self, user_id: str, biometric_features: str) -> Optional[List[str]]:
        """Autentica um usuário e retorna suas roles se a biometria corresponder."""
        for user in self.users:
            if user["user_id"] == user_id:
                decrypted_biometric: str = self.cipher_suite.decrypt(user["encrypted_biometric"].encode()).decode()
                if decrypted_biometric == biometric_features:
                    return user["roles"]
        return None

    def get_user_roles(self, user_id: str) -> Optional[List[str]]:
        """Retorna as roles de um usuário, sem exigir autenticação biométrica."""
        for user in self.users:
            if user["user_id"] == user_id:
                return user["roles"]
        return None


# --- FastAPI Application Setup ---

class UserRegister(BaseModel):
    user_id: str
    biometric_features: str
    roles: List[str]

class UserAuthenticate(BaseModel):
    user_id: str
    biometric_features: str

class UserRoles(BaseModel):
    user_id: str

app = FastAPI(title="Biometric Authentication Service")

db = BiometricDB()

@app.post("/register", response_model=Dict[str, str])
async def register_user(user: UserRegister):
    logging.info(f"Registering user: {user.user_id}")
    db.register(user.user_id, user.biometric_features, user.roles)
    return {"message": "User registered successfully"}

@app.post("/authenticate", response_model=Dict[str, Any])
async def authenticate_user(user: UserAuthenticate):
    logging.info(f"Authenticating user: {user.user_id}")
    roles = db.authenticate(user.user_id, user.biometric_features)
    if roles:
        return {"authenticated": True, "user_id": user.user_id, "roles": roles}
    raise HTTPException(status_code=401, detail="Authentication failed")

@app.get("/roles/{user_id}", response_model=Dict[str, Any])
async def get_user_roles_endpoint(user_id: str = Path(..., title="The ID of the user to retrieve roles for")):
    logging.info(f"Fetching roles for user: {user_id}")
    roles = db.get_user_roles(user_id)
    if roles:
        return {"user_id": user_id, "roles": roles}
    raise HTTPException(status_code=404, detail="User not found")

@app.on_event("startup")
async def startup_event():
    logging.info("Application startup")

@app.on_event("shutdown")
async def shutdown_event():
    logging.info("Application shutdown")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logging.info("Starting up...")
    yield
    # Shutdown
    logging.info("Shutting down...")

app.router.lifespan_context = lifespan

# This block is for running the app directly, e.g., for local testing or within a script.
# In a typical Colab environment for FastAPI, you might run it with uvicorn.run directly
# or use ngrok for exposing it.
if __name__ == "__main__":
    # Example usage for direct execution (e.g., if you were to save this as a .py file and run)
    # For Colab, you might use a different approach to expose the service.
    logging.info("Running Uvicorn server...")
    # This line is usually commented out or handled differently in Colab notebooks
    # to prevent blocking the notebook execution indefinitely.
    # uvicorn.run(app, host="0.0.0.0", port=8000)
    # To run in Colab, you might typically use a background task or a separate thread
    # or expose via ngrok. For demonstration, we'll just show the server start logs.

    # Example to demonstrate DB functionality (not part of FastAPI server start)
    print("\n--- Demonstrating BiometricDB functionality ---")
    db_demo = BiometricDB()
    db_demo.register("alice", "fingerprint_alice_123", ["admin", "user"])
    db_demo.register("bob", "iris_bob_456", ["user"])

    print(f"Alice registered. Users: {db_demo.users}")

    # Authenticate Alice
    auth_alice = db_demo.authenticate("alice", "fingerprint_alice_123")
    print(f"Authenticate Alice (correct): {auth_alice}")

    auth_alice_wrong = db_demo.authenticate("alice", "wrong_fingerprint")
    print(f"Authenticate Alice (incorrect): {auth_alice_wrong}")

    # Get Bob's roles without authentication
    bob_roles = db_demo.get_user_roles("bob")
    print(f"Bob's roles: {bob_roles}")

    # Attempt to get roles for a non-existent user
    charlie_roles = db_demo.get_user_roles("charlie")
    print(f"Charlie's roles: {charlie_roles}")