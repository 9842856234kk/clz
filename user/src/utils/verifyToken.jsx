// src/utils/verifyToken.jsx
export const verifyToken = async (token) => {
  try {
    const response = await fetch("http://localhost:5000/api/verifyToken", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      throw new Error("Token verification failed");
    }

    const data = await response.json();
    return data.isValid; // Adjust this based on your actual response structure
  } catch (error) {
    console.error("Error verifying token:", error);
    return false;
  }
};
