# Chat App Documentation

## Overview

This is a real-time messaging chat application built with **Node.js**, **Express**, **MongoDB**, and **Socket.io**. Users can create accounts, add friends, and send private messages. Messages are stored permanently in MongoDB.

## Features

- User authentication (Signup/Login)
- Add friends by searching for their username
- Accept or reject friend requests
- Private messaging between friends
- Real-time message delivery using **Socket.io**
- Notifications for friend requests and messages
- Secure password hashing with **bcrypt**
- Data persistence with **MongoDB**

---

## Installation

### Prerequisites

Ensure you have the following installed:

- [Node.js](https://nodejs.org/)
- [MongoDB](https://www.mongodb.com/)

### Clone Repository

```sh
git clone https://github.com/LUZAmaxxp/chat-app.git
cd chat-app
```

### Backend Setup

1. Navigate to the server directory:
   ```sh
   cd server
   ```
2. Install dependencies:
   ```sh
   npm install
   ```
3. Create a `.env` file and add:
   ```env
   MONGO_URI=mongodb+srv://your_mongodb_uri
   JWT_SECRET=your_secret_key
   ```
4. Start the server:
   ```sh
   node index.js
   ```

### Frontend Setup

1. Navigate to the client directory:
   ```sh
   cd client
   ```
2. Open `index.html` in a browser.

---

## API Endpoints

### Authentication

#### Register

```http
POST /api/auth/register
```

**Body:**

```json
{
  "username": "exampleUser",
  "email": "user@example.com",
  "password": "securePassword"
}
```

#### Login

```http
POST /api/auth/login
```

**Body:**

```json
{
  "email": "user@example.com",
  "password": "securePassword"
}
```

### Friends

#### Send Friend Request

```http
POST /api/friends/request
```

**Body:**

```json
{
  "senderId": "user1_id",
  "receiverUsername": "friendUsername"
}
```

#### Accept Friend Request

```http
POST /api/friends/accept
```

**Body:**

```json
{
  "requestId": "request_id"
}
```

### Messaging

#### Send Message

```http
POST /api/messages/send
```

**Body:**

```json
{
  "senderId": "user1_id",
  "receiverId": "user2_id",
  "content": "Hello!"
}
```

#### Get Messages

```http
GET /api/messages/:userId/:friendId
```

---

## WebSocket Events

### Client to Server

| Event           | Data                                | Description             |
| --------------- | ----------------------------------- | ----------------------- |
| `sendMessage`   | `{ senderId, receiverId, content }` | Sends a private message |
| `friendRequest` | `{ senderId, receiverUsername }`    | Sends a friend request  |

### Server to Client

| Event                 | Data                    | Description                     |
| --------------------- | ----------------------- | ------------------------------- |
| `newMessage`          | `{ senderId, content }` | Receives a new message          |
| `requestNotification` | `{ senderId }`          | Notifies about a friend request |

---

## Deployment

### Deploy Backend on Vercel

1. Install Vercel CLI:
   ```sh
   npm install -g vercel
   ```
2. Deploy:
   ```sh
   vercel
   ```

### Deploy Frontend on Vercel

1. Navigate to `client` folder:
   ```sh
   cd client
   ```
2. Deploy:
   ```sh
   vercel
   ```

---

## License

This project is open-source and available under the [MIT License](LICENSE).
