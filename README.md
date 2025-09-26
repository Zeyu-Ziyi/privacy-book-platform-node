# Privacy-Preserving Bookstore API

[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Hono](https://img.shields.io/badge/Hono-E36002?style=for-the-badge&logo=hono&logoColor=white)](https://hono.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Stripe](https://img.shields.io/badge/Stripe-626CD9?style=for-the-badge&logo=stripe&logoColor=white)](https://stripe.com/)

A backend service built with Node.js and Hono, designed to implement a privacy-preserving online bookstore. The core of the project is to allow users to purchase and download books without revealing which specific book they bought, using advanced cryptographic techniques like Zero-Knowledge Proofs and Oblivious Transfer.

## ✨ Core Features

-   **User Authentication**: Provides secure user registration and login functionality based on JSON Web Tokens (JWT).
-   **Book Browsing**: Supports public browsing, searching, and viewing of book details.
-   **Stripe Payment Integration**: Uses Stripe to process payments and verifies payment status via webhooks.
-   **Privacy-Preserving Purchase Flow**:
    -   **Zero-Knowledge Proof (ZKP)**: Users use a ZKP to prove they have paid for a book without revealing which one.
    -   **Oblivious Transfer (OT)**: After the ZKP is verified, the server uses an OT protocol to send the user the decryption key for their purchased book, without the server knowing which key the user has chosen.
-   **Secure File Storage**: Book files are encrypted before being stored in an S3-compatible cloud storage service like Cloudflare R2.
-   **WebSocket Communication**: Handles ZKP verification and OT protocol interactions securely and in real-time.

## 🏛️ System Architecture: The Privacy-Preserving Purchase Flow

The core innovation of this project lies in its purchase and download process, which ensures that even if the communication between the user and the server is intercepted, a third party (or even the server itself) cannot link a specific user to the book they purchased.

1.  **Create Order**: The user selects a book's price and generates a ZKP commitment for their choice. They then send a request to `/api/orders` containing the commitment and the price. The server creates a payment intent via Stripe.
2.  **Payment**: The user completes the payment on the frontend. After a successful payment, Stripe notifies the backend via a webhook to update the purchase status in the database to `paid`.
3.  **Connect WebSocket**: The user establishes a WebSocket connection to `/ws/api/purchase/:purchaseId` and authenticates using their JWT.
4.  **ZKP Verification**: The user sends their ZKP proof through the WebSocket. The server uses `snarkjs` to verify that the proof is valid and matches the earlier commitment. Upon successful verification, the purchase status is updated to `verified`.
5.  **Oblivious Transfer (OT)**:
    -   The server initiates the OT protocol and engages in several rounds of cryptographic interaction with the user.
    -   During this process, the server prepares an encrypted version of the decryption key for every book in the database.
    -   The user participates in the protocol according to their choice and ultimately obtains only the correct decryption key for the book they purchased, while the server remains oblivious to which key was taken.
6.  **Get Download Link**: The user requests a time-limited presigned download URL from the server for the specific encrypted book file.
7.  **Completion**: The user downloads and decrypts the book. The server updates the purchase status to `completed`.

## 🛠️ Tech Stack

-   **Web Framework**: Hono
-   **Database**: PostgreSQL (using the `pg` driver)
-   **Authentication**: `hono/jwt` (JWT)
-   **Cryptography**:
    -   `snarkjs`: For ZKP verification
    -   `@noble/curves`: For Elliptic Curve Cryptography in the OT protocol
    -   `bcrypt`: For password hashing
-   **Payments**: Stripe
-   **File Storage**: Cloudflare R2 (via `@aws-sdk/client-s3`)
-   **Real-time Communication**: `ws` (WebSocket)

## 🚀 Setup and Installation

1.  **Clone the repository**
    ```bash
    git clone [https://github.com/your-username/privacy-book-platform-node.git](https://github.com/your-username/privacy-book-platform-node.git)
    cd privacy-book-platform-node
    ```

2.  **Install dependencies**
    ```bash
    npm install
    ```

3.  **Set up environment variables**
    Create a `.env` file in the project's root directory and fill in the following values:
    ```env
    # Database connection string
    DATABASE_URL="postgresql://username:password@host:port/database"

    # JWT Secret
    JWT_SECRET="your_strong_jwt_secret"

    # Stripe API Keys
    STRIPE_API_KEY="sk_test_..."
    STRIPE_WEBHOOK_SECRET="whsec_..."

    # Cloudflare R2 (or any S3-compatible storage) credentials
    R2_ACCOUNT_ID="..."
    R2_ACCESS_KEY_ID="..."
    R2_SECRET_ACCESS_KEY="..."
    R2_BUCKET_NAME="..."

    # Server Port
    PORT=3000
    ```

4.  **Run the project**
    ```bash
    npm run dev # Or another start command defined in your package.json
    ```

    The server will start at `http://localhost:3000`.

## 📦 Scripts

The project includes a helper script for encrypting and uploading books.

### Encrypt and Upload Books (`src/upload.ts`)

This script reads a local file, encrypts it using the AES-256-GCM algorithm with a randomly generated key, and uploads the encrypted file to the R2 bucket.

**How to use:**
```bash
npx tsx src/upload.ts /path/to/your/book.pdf