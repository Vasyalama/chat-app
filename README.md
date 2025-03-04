# User Chat Application

## Prerequisites

Before you begin, ensure you have the following installed on your machine:

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

## Getting Started

To get the project up and running, follow these steps:

### 1. Clone the Repository

First, clone the repository to your local machine:

```bash
git clone <repository-url>
cd <repository-directory>
```

### 2. Edit the .env file with proper environment variables

```
DB_HOST=
DB_USER=
DB_PASSWORD=
DB_NAME=
DB_PORT=
ACCESS_TOKEN_EXPIRATION=
REFRESH_TOKEN_EXPIRATION=
ACCESS_TOKEN_SECREt=
REFRESH_TOKEN_SECRET=
SMTP_PASSWORD=
SMTP_EMAIL_FROM=
```
### 3. Build and Run the Application

```bash
docker-compose up --build
```

This command will:
- Build the Docker image for the application.
- Start the MySQL database container.
- Start the application container.

### 4. Access the Application

Once the containers are up and running, you can access the application at:
```
http://localhost:8080
```

